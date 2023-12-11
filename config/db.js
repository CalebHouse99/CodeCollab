/* MONGODB CONNECTION */

/* Calling in mongoose */
const mongoose = require('mongoose').set('strictQuery', false);

/* Calling in config package */
const config = require('config');

/* To get any value in the json file (mongo URI) */
const db = config.get('mongoURI');



/* after trying to connect to db, it will give us a promise. Creating async arrow function. Want to run mongoose.connect inside try or catch block. Await because mongoose connection is returning promise. */
const connectDB = async() => {
    try {
        await mongoose.connect(db, {
            useNewUrlParser: true


        });

        console.log('MongoDB Connected...')
    } catch (err) {
        console.error(err.message)
            // exit process with failure
        process.exit(1);
    }
}

/* export db */
module.exports = connectDB;