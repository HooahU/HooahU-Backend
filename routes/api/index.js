const router = require('express').Router();
// const shuttle = require('./shuttle');
// const pedalo = require('./pedalo');
// const notice = require('./notice');
// const weather = require('./weather');
// const sugang = require('./sugang');
// const map = require('./map');
const auth = require('./auth');
const authMiddleware = require('../../middlewares/auth');

router.use('/auth', auth);
// router.use('/shuttle', shuttle);
// router.use('/pedalo', pedalo);
// router.use('/notice', notice);
// router.use('/weather', weather);

// router.use('/map', authMiddleware);
// router.use('/map', map);

// router.use('/sugang', authMiddleware);
// router.use('/sugang', sugang)

module.exports = router;
