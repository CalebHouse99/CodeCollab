/* Calling in Express */
const express = require('express');
const connectDB = require('./config/db');
const path = require('path');

/* App variable with express */
const app = express();

/* Connect Dabatase */
connectDB();

// Init middleware
app.use(express.json({ extended: false }));

// Define Routes
app.use('/api/users', require('./routes/api/users'));
app.use('/api/auth', require('./routes/api/auth'));
app.use('/api/profile', require('./routes/api/profile'));
app.use('/api/posts', require('./routes/api/posts'));

if(process.env.NODE_ENV === 'production') {
    app.use(express.static('client/build'));
    app.get('*', (req, res) => {
        res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
    })
}

const PORT = process.env.PORT || 5000;

/* Listen to app variable on port, added callback message once it connects */
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));