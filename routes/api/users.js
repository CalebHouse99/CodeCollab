const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../../models/User'); // Ensure this is correctly imported

// @route POST api/users
// @desc Register user
// @access Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(), 
    check('email', 'Please include a valid email').isEmail(), 
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
    console.log('POST /api/users called');
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors in POST /api/users:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    console.log('Request Body:', req.body);

    try {
        let user = await User.findOne({ email });
        console.log('User found in POST /api/users:', user);

        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
        }

        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        });

        user = new User({
            name,
            email,
            avatar,
            password
        });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();
        console.log('User saved:', user);

        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(payload, config.get('jwtSecret'), { expiresIn: 360000 },
            (err, token) => {
                if (err) {
                    console.error('Error signing token in POST /api/users:', err);
                    throw err;
                }
                console.log('Token generated for new user:', token);
                res.json({ token });
            }
        );

    } catch (err) {
        console.error('Error in POST /api/users:', err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;