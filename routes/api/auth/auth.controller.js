const jwt = require('jsonwebtoken');
const User = require('../../../models/user');
const crypto = require('crypto');
const config = require('../../../config');
/*
    POST /api/auth
    {
        username,
        password
    }
*/

exports.register = (req, res) => {
	const { username, password, saySomething } = req.body;
	const encrypted = crypto.createHmac('sha1', config.secret)
		.update(password)
		.digest('base64');
	User.findOne({ username: username },(err, user) => {
		if (err) return res.status(500).json({ error: err });
		if (user) return res.status(406).json({ message:'username exists' });
		let newUser = new User({
			username,
			password: encrypted,
			// saySomething,
			// profileImg : 'https://s3.ap-northeast-2.amazonaws.com/reviewany/KakaoTalk_2017-09-25-16-51-00_Photo_65.jpeg'
		});
		newUser.save( (err) => {
			if (err) return res.status(500).json({ error:err });
			return res.status(200).json({ message: 'registered successfully' });
		});
	});
};

exports.login = (req, res) => {
	const { username, password } = req.body;
	const secret = req.app.get('jwt-secret');

	User.findOne({ username: username }, (err, user) => {
		if (err) return res.status(500).json({ error: err });
		if (!user) return res.status(406).json({ message:'login failed' });
		const encrypted = crypto.createHmac('sha1', config.secret)
			.update(password)
			.digest('base64');
		if (user.password === encrypted) {
			jwt.sign(
				{
					_id: user._id,
					username: user.username,
					admin: user.admin
				},
				secret,
				{
					expiresIn: '7d',
					issuer: 'yoonjeewoo',
					subject: 'userInfo'
				}, (err, token) => {
					if (err) return res.status(406).json({ message:'login failed' });
					return res.status(200).json({
						message: 'logged in successfully',
						token
					});
				});
		} else {
			return res.status(406).json({ message:'login failed' });
		}
	});

};
