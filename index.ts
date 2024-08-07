import Elysia, {error, t} from 'elysia'
import {MongoClient, ObjectId} from "mongodb";
import {staticPlugin} from '@elysiajs/static';
import {jwt} from '@elysiajs/jwt'
import axios from "axios";

const client = new MongoClient(process.env.MONGO_DB_CONNECTION_STRING ?? '');
const secretKey = process.env.JWT_SECRET_KEY

//732111593

async function init() {
    try {
        await client.connect();
        console.log('Подключено к MongoDB');
        const dbName = 'default_db';
        const db = client.db(dbName);
        new Elysia()
            .use(
                jwt({
                    name: 'jwt',
                    secret: secretKey
                })
            )
            .post('/create-payment', async ({body}) => {
                const paymentCollection = db.collection('payments')
                const payment: any = await paymentCollection.insertOne({...body});
                return {message: 'Payment created.', payment: payment};
            })
            .get('/get-payment/:email', async ({params: {email}}) => {
                const payment = await db.collection('payments').findOne({description: email})
                const user = await db.collection('users').findOne({email: email})
                if (payment&&!user) {
                    return {payment}
                }
                else{
                    return {message:'User already exists'}
                }
            })
            .post('/update-payment/:id', async ({body, params: {id}}) => {
                const paymentCollection = db.collection('payments')
                const payment: any = await paymentCollection.findOneAndUpdate({id: id}, {$set: {...body}});
                console.log(payment, body, id)
                return {message: 'Payment created.', payment: payment};
            })
            .post('/register', async ({body}) => {
                const usersCollection = db.collection('users')
                const {email, password, phone} = body;
                const {plan}=body
                const hashedPassword = await Bun.password.hash(password, {algorithm: 'bcrypt'});

                // Get the current date
                const currentDate = new Date();

                const oneMonthAhead = new Date(currentDate);

                oneMonthAhead.setMonth(currentDate.getMonth() + 1);

                if (oneMonthAhead.getDate() < currentDate.getDate()) {
                    oneMonthAhead.setDate(0);
                }


                const currentDateYear = new Date();

                const oneYearAhead = new Date(currentDate);

                oneYearAhead.setMonth(currentDateYear.getMonth() + 1);

                if (oneYearAhead.getDate() < currentDateYear.getDate()) {
                    oneYearAhead.setDate(0);
                }

                const user = await usersCollection.insertOne({
                    email,
                    phone,
                    password: hashedPassword,
                    subscribeTill: plan=='year'?oneYearAhead.toISOString():oneMonthAhead.toISOString()
                });

                return {message: 'User registered successfully', userId: user.insertedId};
            }, {
                body: t.Object({
                    email: t.String(),
                    password: t.String(),
                    phone: t.String()
                })
            })
            .post('/login', async ({jwt, body}) => {
                const {email, password} = body;
                const usersCollection = db.collection('users')
                const user = await usersCollection.findOne({email});
                if (!user) {
                    return {message: 'Invalid email or password'};
                }

                const isPasswordValid = await Bun.password.verify(password, user.password);
                if (!isPasswordValid) {
                    return {message: 'Invalid email or password'};
                }

                const token = await jwt.sign({userId: user._id, email: user.email}, secretKey, {expiresIn: '1d'});

                // console.log(token)

                return {message: 'Login successful', token, user: {userId: user._id, email: user.email}};
            })
            .derive(async ({headers, jwt}) => {
                const auth = headers['authorization']
                // console.log(headers)
                const token = auth && auth.split(' ')[1];

                if (!token) {
                    return new Error('Unauthorized');
                }

                try {
                    const decoded = await jwt.verify(token, secretKey);
                    return {
                        user: decoded
                    }
                } catch (error) {
                    return error;
                }
            })
            .onError(({code, error}) => {
                return new Response(error.toString())
            })
            .get('/user/', async ({user}) => {
                const userRecord = await db.collection('users').findOne({_id: new ObjectId(user.userId)})
                console.log(userRecord, user.userId)
                return userRecord
                // return user
            })
            .get('/articles', async ({user}) => {
                const articles = await axios.get('https://d5dtvdk9rps5pmn5i7oh.apigw.yandexcloud.net/parserInfo?date=2024-07-26')
                console.log(articles.data)
                return articles.data
            })
            .post('/update-profile/', async ({body, user}) => {
                const usersCollection = db.collection('users')
                console.log(body, {...body})

                if (body.password) {

                    const usersCollection = db.collection('users');

                    const newPassword = body.password;

                    // Hash the new password
                    const hashedNewPassword = await Bun.password.hash(newPassword, {algorithm: 'bcrypt'});

                    // Update the user's password in the database
                    // await usersCollection.findOneAndUpdate(
                    //     {_id: new ObjectId(user.userId)},
                    //     {
                    //         $set: {
                    //             password: hashedNewPassword,
                    //         },
                    //     }
                    // );
                    const userUpdate = await usersCollection.findOneAndUpdate({_id: new ObjectId(user.userId)}, {
                        $set: {
                            ...body, password: hashedNewPassword
                        }
                    });
                    return {message: 'User info updated successfully', user: userUpdate};
                } else {
                    const userUpdate = await usersCollection.findOneAndUpdate({_id: new ObjectId(user.userId)}, {
                        $set: {
                            ...body,
                        }
                    });
                    return {message: 'User info updated successfully', user: userUpdate};
                }
            })
            .post('/view-post/', async ({body, user}) => {
                const usersCollection = db.collection('users')

                const post = JSON.parse(body.post)

                // console.log(post)

                const userUpdate = await usersCollection.findOneAndUpdate({_id: new ObjectId(user.userId)}, {
                    $push: {
                        viewed: post
                    }
                });

                console.log(userUpdate, 'UPDATED')

                return {message: 'Post viewed', user: userUpdate};

            })
            .post('/save-post/', async ({body, user}) => {
                const usersCollection = db.collection('users')

                const post = JSON.parse(body.post)

                // console.log(post)

                const userUpdate = await usersCollection.findOneAndUpdate({_id: new ObjectId(user.userId)}, {
                    $push: {
                        saved: post
                    }
                });

                console.log(userUpdate, 'UPDATED')

                return {message: 'Post viewed', user: userUpdate};

            })
            .listen(parseInt(process.env.PORT ?? "3000"), () => {
                console.log(`Приложение запущено на порте ${process.env.PORT ?? "3000"}`)
            })
    } catch
        (e) {
        console.log(e)
    }
}

init()

