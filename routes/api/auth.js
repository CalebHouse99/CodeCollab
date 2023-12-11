const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const config = require('config');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        console.log('GET /api/auth called');
        const user = await User.findById(req.user.id).select('-password');
        console.log('User found:', user);
        res.json(user);
    } catch (err) {
        console.error('Error in GET /api/auth:', err.message);
        res.status(500).send('Server error');
    }
});

// @route POST api/auth
// @desc Authenticate user and get token
// @access Public
router.post('/', [
    check('email', 'Please include a valid email').isEmail(), 
    check('password', 'Password is required').exists()
], async (req, res) => {
    console.log('POST /api/auth called');
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors in POST /api/auth:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    console.log('Request Body:', req.body);

    try {
        let user = await User.findOne({ email });
        console.log('User found in POST /api/auth:', user);

        if (!user) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        console.log('Password match:', isMatch);

        if (!isMatch) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(payload, config.get('jwtSecret'), { expiresIn: 360000 },
            (err, token) => {
                if (err) {
                    console.error('Error signing token in POST /api/auth:', err);
                    throw err;
                }
                console.log('Token generated:', token);
                res.json({ token });
            }
        );

    } catch (err) {
        console.error('Error in POST /api/auth:', err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
