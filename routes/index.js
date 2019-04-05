var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var { body,validationResult } = require('express-validator/check');
var { sanitizeBody } = require('express-validator/filter');
var bcrypt = require('bcryptjs');
var saltRounds = 10;
var moment = require('moment');
var mysql = require('mysql');

// Middlewares
function isNotAuthenticated(req, res, next) {
    if (!(req.isAuthenticated())){
        return next();
    }
    res.redirect('/403');
}

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}

// extract word after first slash and word after second slash
function isResource(req, res, next) {
    let uri = req._parsedOriginalUrl.path;
    if (uri.includes('/api')){
        uri = uri.substring(4);
    }
    if (uri.includes('?')){
        uri = uri.substring(0, uri.indexOf("?"));
    }
    uri = uri.substring(1);
    uri = uri.substring(0, uri.indexOf('/'));
    // let table = uri.substring(0, uri.length - 1);
    let table = uri;
    let id = Number(req.params.id);
    let connection = mysql.createConnection({
        host     : process.env.DB_HOSTNAME,
        user     : process.env.DB_USERNAME,
        password : process.env.DB_PASSWORD,
        port     : process.env.DB_PORT,
        database : process.env.DB_NAME,
        multipleStatements: true
    });
    connection.query('SELECT id FROM ' + table + ' WHERE id = ?', [id], function(error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        if (results.length === 0){
            res.render('404');
        }
        else {
            next();
        }
    });
}

// function isOwnResource(req, res, next) {
//     let uri = req._parsedOriginalUrl.path;
//     uri = uri.substring(1);
//     uri = uri.substring(0, uri.lastIndexOf('/'));
//     if (uri.includes('/')){
//         uri = uri.substring(0, uri.lastIndexOf('/'));
//     }
//     uri = uri.substring(0, uri.length - 1);
//     let table = uri;
//     let resourceid = req.params.id;
//     if (table === 'user') {
//         if (req.user.id !== Number(resourceid)) {
//             res.render('403');
//         } else {
//             next();
//         }
//     } else {
//         var connection = mysql.createConnection({
//             host     : process.env.DB_HOSTNAME,
//             user     : process.env.DB_USERNAME,
//             password : process.env.DB_PASSWORD,
//             port     : process.env.DB_PORT,
//             database : process.env.DB_NAME,
//             multipleStatements: true
//         });
//         connection.query('SELECT userid FROM ' + table + ' WHERE id = ?', [resourceid], function (error, results, fields) {
//             // error will be an Error if one occurred during the query
//             // results will contain the results of the query
//             // fields will contain information about the returned results fields (if any)
//             if (error) {
//                 throw error;
//             }
//             if (req.user.id !== results[0].userid) {
//                 res.render('403');
//             } else {
//                 next();
//             }
//         });
//     }
// }

/* GET home page. */
// if user is logged in return feed page else return home page
router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
      connection.query('SELECT * FROM addresses ORDER BY date_created DESC; SELECT count(*) as count FROM addresses',
          function (error, results, fields) {
              if (error) {
                  throw error;
              }
              res.render('addresses/index', {
                  title: 'Addresses',
                  req: req,
                  results: results,
                  alert: req.flash('alert')
              });
          }
      );
  } else {
      res.redirect('/login');
  }
});

// USER ROUTES
router.get('/users/new', isNotAuthenticated, function(req, res, next){
    res.render('users/new', {
        title: 'Sign up',
        req: req,
        errors: req.flash('errors'),
        inputs: req.flash('inputs')
    });
});

// validate user input and if wrong redirect to register page with errors and inputs else save data into
// database and redirect to login with flash message
router.post('/users', isNotAuthenticated, [
    body('email', 'Empty email.').not().isEmpty(),
    body('password', 'Empty password.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('password', 'Password must be between 5-60 characters.').isLength({min:5, max:60}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail(),
    body('password', 'Password must contain one lowercase character, one uppercase character, a number, and ' +
        'a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i")
], function(req, res, next){
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username});
        res.redirect('/users/new');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('password').trim().escape();
        sanitizeBody('username').trim().escape();
        const email = req.body.email;
        const password = req.body.password;
        const username = req.body.username;
        bcrypt.hash(password, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            if (err) {
                throw error;
            }
            connection.query('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                [email, username, hash], function (error, results, fields) {
                    // error will be an Error if one occurred during the query
                    // results will contain the results of the query
                    // fields will contain information about the returned results fields (if any)
                    if (error) {
                        throw error;
                    }
                    req.flash('alert', 'You have successfully registered.');
                    res.redirect('/login');
                });
        });
    }
});

router.get('/users/:id', isResource, isAuthenticated, function(req, res){
    connection.query('SELECT id, email, username, description, imageurl, datecreated, level FROM users WHERE id = ?',
        [req.params.id],
        function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            console.log(results);
            res.render('users/show', {
                                title: 'Profile',
                                req: req,
                                results: results,
                                moment: moment,
                                alert: req.flash('alert')
                            });
        });
});

router.get('/users/:id/edit', isResource, isAuthenticated, function(req, res){
    if (req.user.id === Number(req.params.id)){
        connection.query('SELECT id, email, username, description FROM users WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('users/edit', {
                    title: 'Edit profile',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, [
    body('email', 'Empty email.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('description', 'Description must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('username').trim().escape();
        sanitizeBody('description').trim().escape();
        const email = req.body.email;
        const username = req.body.username;
        const description = req.body.description;
        connection.query('UPDATE users SET email = ?, username = ?, description = ? WHERE id = ?',
            [email, username, description, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Profile edited.');
                res.redirect(req._parsedOriginalUrl.pathname);
            });
    }
});

router.delete('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, function(req, res){
    connection.query('DELETE FROM users WHERE id = ?', [req.params.id], function (error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        req.flash('alert', 'Profile deleted.');
        req.logout();
        res.redirect('/');
    });
});


// address routes
router.get('/addresses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('addresses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/addresses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
},[
            body('building_number', 'Empty building number.').not().isEmpty(),
            body('street', 'Empty street.').not().isEmpty(),
            body('city', 'Empty city.').not().isEmpty(),
            body('state', 'Empty state.').not().isEmpty(),
            body('country', 'Empty country.').not().isEmpty(),
            body('zip', 'Empty zip.').not().isEmpty(),
            body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
            body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
            body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
            body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
            body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
            body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
        ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
                state: req.body.state, country: req.body.country, zip: req.body.zip});
            res.redirect('/addresses/new');
        }
        else {
            sanitizeBody('building_number').trim().escape();
            sanitizeBody('street').trim().escape();
            sanitizeBody('city').trim().escape();
            sanitizeBody('state').trim().escape();
            sanitizeBody('country').trim().escape();
            sanitizeBody('zip').trim().escape();
            const building_number = req.body.building_number;
            const street = req.body.street;
            const city = req.body.city;
            const state = req.body.state;
            const country = req.body.country;
            const zip = req.body.zip;
            connection.query('INSERT INTO addresses (building_number, street, city, state, country, zip) VALUES ' +
                '(?, ?, ?, ?, ?, ?)', [building_number, street, city, state, country, zip], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address created.');
                res.redirect('/');
            });
        }
    }
);

router.get('/addresses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, building_number, street, city, state, country, zip FROM addresses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('addresses/edit', {
                    title: 'Edit address',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
}, [
    body('building_number', 'Empty building number.').not().isEmpty(),
    body('street', 'Empty street.').not().isEmpty(),
    body('city', 'Empty city.').not().isEmpty(),
    body('state', 'Empty state.').not().isEmpty(),
    body('country', 'Empty country.').not().isEmpty(),
    body('zip', 'Empty zip.').not().isEmpty(),
    body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
    body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
    body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
    body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
    body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
    body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
            state: req.body.state, country: req.body.country, zip: req.body.zip});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('building_number').trim().escape();
        sanitizeBody('street').trim().escape();
        sanitizeBody('city').trim().escape();
        sanitizeBody('state').trim().escape();
        sanitizeBody('country').trim().escape();
        sanitizeBody('zip').trim().escape();
        const building_number = req.body.building_number;
        const street = req.body.street;
        const city = req.body.city;
        const state = req.body.state;
        const country = req.body.country;
        const zip = req.body.zip;
        connection.query('UPDATE addresses SET building_number = ?, street = ?, city = ?, state = ?,' +
            'country = ?, zip = ? WHERE id = ?',
            [building_number, street, city, state, country, zip, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address edited.');
                res.redirect('/');
            });
    }
});

router.delete('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            connection.query('DELETE FROM addresses WHERE id = ?', [req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address deleted.');
                res.redirect('/');
            });
        } else {
            res.render('403');
        }
        });

// customer routes
router.get('/customers', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM customers ORDER BY date_created DESC; SELECT count(*) as count FROM customers',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('customers/index', {
                    title: 'Customers',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/customers/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('customers/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/customers', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/customers/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO customers (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customer created.');
                res.redirect('/customers');
            });
        }
    }
);

router.get('/customers/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM customers WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('customers/edit', {
                    title: 'Edit customer',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/customers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE customers SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customer edited.');
                res.redirect('/customers');
            });
    }
});

router.delete('/customers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM customers WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Customer deleted.');
            res.redirect('/customers');
        });
    } else {
        res.render('403');
    }
});

// customerstaff routes
router.get('/customersstaffs', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM customersstaffs ORDER BY date_created DESC; SELECT count(*) as count FROM customersstaffs',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('customersstaffs/index', {
                    title: 'Customersstaffs',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/customersstaffs/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('customersstaffs/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/customersstaffs', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('customer_id', 'Empty customer_id.').not().isEmpty(),
        body('staff_id', 'Empty staff_id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {customer_id: req.body.customer_id, staff_id: req.body.staff_id
            });
            res.redirect('/customersstaffs/new');
        }
        else {
            sanitizeBody('customer_id').trim().escape();
            sanitizeBody('staff_id').trim().escape();
            const customer_id = req.body.customer_id;
            const staff_id = req.body.staff_id;
            connection.query('INSERT INTO customersstaffs (customer_id, staff_id) VALUES ' +
                '(?, ?)', [customer_id, staff_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customerstaff created.');
                res.redirect('/customersstaffs');
            });
        }
    }
);

router.get('/customersstaffs/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, customer_id, staff_id FROM customersstaffs WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('customersstaffs/edit', {
                    title: 'Edit customerstaff',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/customersstaffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('customer_id', 'Empty customer_id.').not().isEmpty(),
    body('staff_id', 'Empty staff_id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {customer_id: req.body.customer_id, staff_id: req.body.staff_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('customer_id').trim().escape();
        sanitizeBody('staff_id').trim().escape();
        const customer_id = req.body.customer_id;
        const staff_id = req.body.staff_id;
        connection.query('UPDATE customersstaffs SET customer_id = ?, staff_id = ? WHERE id = ?',
            [customer_id, staff_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customerstaff edited.');
                res.redirect('/customersstaffs');
            });
    }
});

router.delete('/customersstaffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM customersstaffs WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Customerstaff deleted.');
            res.redirect('/customersstaffs');
        });
    } else {
        res.render('403');
    }
});

// customerstaffinventory routes
router.get('/customersstaffsinventories', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM customersstaffsinventories ORDER BY date_created DESC; SELECT count(*) as count FROM customersstaffsinventories',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('customersstaffsinventories/index', {
                    title: 'Customersstaffsinventories',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/customersstaffsinventories/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('customersstaffsinventories/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/customersstaffsinventories', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('customersstaffs_id', 'Empty customers staffs id.').not().isEmpty(),
        body('inventories_id', 'Empty inventories id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {customersstaffs_id: req.body.customersstaffs_id, nventories_id: req.body.nventories_id
            });
            res.redirect('/customersstaffsinventories/new');
        }
        else {
            sanitizeBody('customersstaffs_id').trim().escape();
            sanitizeBody('inventories_id').trim().escape();
            const customersstaffs_id = req.body.customersstaffs_id;
            const inventories_id = req.body.inventories_id;
            connection.query('INSERT INTO customersstaffsinventories (customersstaffs_id, inventories_id) VALUES ' +
                '(?, ?)', [customersstaffs_id, inventories_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customersstaffsinventories created.');
                res.redirect('/customersstaffsinventories');
            });
        }
    }
);

router.get('/customersstaffsinventories/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, customersstaffs_id, inventories_id FROM customersstaffsinventories WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('customersstaffsinventories/edit', {
                    title: 'Edit customerstaffinventory',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/customersstaffsinventories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('customersstaffs_id', 'Empty customers staffs id.').not().isEmpty(),
    body('inventories_id', 'Empty inventories id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {customersstaffs_id: req.body.customersstaffs_id, nventories_id: req.body.nventories_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('customersstaffs_id').trim().escape();
        sanitizeBody('inventories_id').trim().escape();
        const customersstaffs_id = req.body.customersstaffs_id;
        const inventories_id = req.body.inventories_id;
        connection.query('UPDATE customersstaffsinventories SET customersstaffs_id = ?, inventories_id = ? WHERE id = ?',
            [customersstaffs_id, inventories_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Customersstaffsinventories edited.');
                res.redirect('/customersstaffsinventories');
            });
    }
});

router.delete('/customersstaffsinventories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM customersstaffsinventories WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Customersstaffsinventories deleted.');
            res.redirect('/customersstaffsinventories');
        });
    } else {
        res.render('403');
    }
});

// gender routes
router.get('/genders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM genders ORDER BY date_created DESC; SELECT count(*) as count FROM genders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('genders/index', {
                    title: 'Genders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/genders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('genders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/genders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('gender', 'Empty gender.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {gender: req.body.gender});
            res.redirect('/genders/new');
        }
        else {
            sanitizeBody('gender').trim().escape();
            const gender = req.body.gender;
            connection.query('INSERT INTO genders (gender) VALUES ' +
                '(?)', [gender], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender created.');
                res.redirect('/genders');
            });
        }
    }
);

router.get('/genders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, gender FROM genders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('genders/edit', {
                    title: 'Edit gender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('gender', 'Empty gender.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {gender: req.body.gender});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('gender').trim().escape();
        const gender = req.body.gender;
        connection.query('UPDATE genders SET gender = ? WHERE id = ?',
            [gender, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender edited.');
                res.redirect('/genders');
            });
    }
});

router.delete('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM genders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Gender deleted.');
            res.redirect('/genders');
        });
    } else {
        res.render('403');
    }
});

// inventories routes
router.get('/inventories', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM inventories ORDER BY date_created DESC; SELECT count(*) as count FROM inventories',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('inventories/index', {
                    title: 'Inventories',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/inventories/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('inventories/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/inventories', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('stock', 'Empty stock.').not().isEmpty(),
        body('manufacturer_id', 'Empty manufacturer id.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description, stock: req.body.stock,
                manufacturer_id: req.body.manufacturer_id
            });
            res.redirect('/inventories/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('stock').trim().escape();
            sanitizeBody('manufacturer_id').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            const stock = req.body.stock;
            const manufacturer_id = req.body.manufacturer_id;
            connection.query('INSERT INTO inventories (name, description, stock, manufacturer_id) VALUES ' +
                '(?,?,?,?)', [name, description, stock, manufacturer_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Inventory created.');
                res.redirect('/inventories');
            });
        }
    }
);

router.get('/inventories/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description, stock, manufacturer_id FROM inventories WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('inventories/edit', {
                    title: 'Edit inventory',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/inventories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('stock', 'Empty stock.').not().isEmpty(),
    body('manufacturer_id', 'Empty manufacturer id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description, stock: req.body.stock,
            manufacturer_id: req.body.manufacturer_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('stock').trim().escape();
        sanitizeBody('manufacturer_id').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        const stock = req.body.stock;
        const manufacturer_id = req.body.manufacturer_id;
        connection.query('UPDATE inventories SET name = ?, description = ?, stock = ?, manufacturer_id = ? WHERE id = ?',
            [name, description, stock, manufacturer_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Inventory edited.');
                res.redirect('/inventories');
            });
    }
});

router.delete('/inventories/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM inventories WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Inventory deleted.');
            res.redirect('/inventories');
        });
    } else {
        res.render('403');
    }
});

// manufacturer routes
router.get('/manufacturers', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM manufacturers ORDER BY date_created DESC; SELECT count(*) as count FROM manufacturers',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('manufacturers/index', {
                    title: 'Manufacturers',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/manufacturers/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('manufacturers/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/manufacturers', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('contact_number', 'Empty contact number.').not().isEmpty(),
        body('contact_person_first_name', 'Empty contact person first name.').not().isEmpty(),
        body('contact_person_last_name', 'Empty contact person last name.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, contact_number: req.body.contact_number, contact_person_first_name
                    : req.body.contact_person_first_name, contact_person_last_name: contact_person_last_name
            });
            res.redirect('/manufacturers/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('contact_number').trim().escape();
            sanitizeBody('contact_person_first_name').trim().escape();
            sanitizeBody('contact_person_last_name').trim().escape();
            const name = req.body.name;
            const contact_number = req.body.contact_number;
            const contact_person_first_name = req.body.contact_person_first_name;
            const contact_person_last_name = req.body.contact_person_last_name;
            connection.query('INSERT INTO manufacturers (name, contact_number, contact_person_first_name, contact_person_last_name) VALUES ' +
                '(?, ?, ?,?)', [name, contact_number, contact_person_first_name, contact_person_last_name], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Manufacturer created.');
                res.redirect('/manufacturers');
            });
        }
    }
);

router.get('/manufacturers/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, contact_number, contact_person_first_name, contact_person_last_name FROM manufacturers WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('manufacturers/edit', {
                    title: 'Edit manufacturer',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/manufacturers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('contact_number', 'Empty contact number.').not().isEmpty(),
    body('contact_person_first_name', 'Empty contact person first name.').not().isEmpty(),
    body('contact_person_last_name', 'Empty contact person last name.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, contact_number: req.body.contact_number, contact_person_first_name
                : req.body.contact_person_first_name, contact_person_last_name: contact_person_last_name});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('contact_number').trim().escape();
        sanitizeBody('contact_person_first_name').trim().escape();
        sanitizeBody('contact_person_last_name').trim().escape();
        const name = req.body.name;
        const contact_number = req.body.contact_number;
        const contact_person_first_name = req.body.contact_person_first_name;
        const contact_person_last_name = req.body.contact_person_last_name;
        connection.query('UPDATE manufacturers SET name = ?, contact_number = ?, contact_person_first_name = ?, contact_person_last_name = ? WHERE id = ?',
            [name, contact_number, contact_person_first_name, contact_person_last_name, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Manufacturer edited.');
                res.redirect('/manufacturers');
            });
    }
});

router.delete('/manufacturers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM manufacturers WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Manufacturer deleted.');
            res.redirect('/manufacturers');
        });
    } else {
        res.render('403');
    }
});

// staff routes
router.get('/staffs', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM staffs ORDER BY date_created DESC; SELECT count(*) as count FROM staffs',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('staffs/index', {
                    title: 'Staffs',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/staffs/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('staffs/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/staffs', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/staffs/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO staffs (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Staff created.');
                res.redirect('/staffs');
            });
        }
    }
);

router.get('/staffs/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM staffs WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('staffs/edit', {
                    title: 'Edit staff',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/staffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE staffs SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Staff edited.');
                res.redirect('/staffs');
            });
    }
});

router.delete('/staffs/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM staffs WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Staff deleted.');
            res.redirect('/staffs');
        });
    } else {
        res.render('403');
    }
});

router.get('/login', isNotAuthenticated, function(req, res, next){
    res.render('login', {
        title: 'Log in',
        req: req,
        errors: req.flash('errors'),
        input: req.flash('input'),
        alert: req.flash('alert')
    });
});

router.post('/login', isNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })
);

router.get('/logout', isAuthenticated, function(req, res){
    req.logout();
    res.redirect('/login');
});

module.exports = router;
