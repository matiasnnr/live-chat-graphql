const { User } = require('../models');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/env.json');
const { UserInputError, AuthenticationError } = require('apollo-server');
const { Op } = require('sequelize');

module.exports = {
    Query: {
        // getUsers: async (parent, args, context, info) => {
        getUsers: async (_, __, ctx) => {

            try {

                let user;

                if (ctx.req && ctx.req.headers.authorization) {
                    const token = ctx.req.headers.authorization.split('Bearer ')[1];
                    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
                        if (err) {
                            throw new AuthenticationError('Unauthenticated');
                        }

                        user = decodedToken;

                    })
                }

                // esta query con sequelize encontrara todos los usuarios exepto a user.username
                const users = await User.findAll({ where: { username: { [Op.ne]: user.username } } });

                return users;
            } catch (error) {
                console.log(error);
                throw error;
            }
        },
        login: async (_, args) => {
            const { username, password } = args;
            let errors = {};

            try {

                if (username.trim() === '') errors.username = 'Username must not be empty';
                if (password.trim() === '') errors.password = 'Password must not be empty';

                if (Object.keys(errors).length > 0) {
                    throw new UserInputError('Bad input', { errors })
                }

                const user = await User.findOne({ where: { username } });

                if (!user) {
                    errors.username = 'User not found';
                    throw new UserInputError('User not found', { errors })
                }

                const correctPassword = await bcrypt.compare(password, user.password);

                if (!correctPassword) {
                    errors.password = 'Password is incorrect';
                    throw new UserInputError('Password is incorrect', { errors });
                    // throw new AuthenticationError('Password is incorrect', { errors }); deja pasar con la contraseña erronea y no arroja el error
                }

                // obviamente el secret token no se debe colocar acá (debe ir en .env), pero por motivos de desarrollo rápido lo dejamos así
                const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: 60 * 60 });

                return {
                    ...user.toJSON(),
                    createdAt: user.createdAt.toISOString(),
                    token
                }

            } catch (error) {

                console.log(error);
                throw error;

            }
        }
    },
    Mutation: {
        // register: async (parent, args, context, info) => {
        register: async (_, args) => {
            let { username, email, password, confirmPassword } = args;
            let errors = {};

            try {
                // TODO: Validate input data
                if (username.trim() === '') errors.username = 'Username must not be empty';
                if (email.trim() === '') errors.email = 'Email must not be empty';
                if (password.trim() === '') errors.password = 'Password must not be empty';
                if (confirmPassword.trim() === '') errors.confirmPassword = 'Confirm Password must not be empty';

                if (password !== confirmPassword) errors.confirmPassword = 'Passwords must match';

                // TODO: Check if username / email exists
                // const userByUsername = await User.findOne({ where: { username } });
                // const userByEmail = await User.findOne({ where: { email } });

                // if (userByUsername) errors.username = 'Username is taken';
                // if (userByEmail) errors.email = 'Email is taken';

                if (Object.keys(errors).length > 0) throw errors;

                // Hash password
                password = await bcrypt.hash(password, 6);

                // Create user
                const user = await User.create({ username, email, password });

                // Return user
                return user;
            } catch (error) {
                console.log(error);
                if (error.name === 'SequelizeUniqueConstraintError') {
                    error.errors.forEach(e => (errors[e.path.split('.')[1]] = `${e.path.split('.')[1]} is already taken`));
                } else if (error.name === 'SequelizeValidationError') {
                    error.errors.forEach(e => errors[e.path] = e.message);
                }

                throw new UserInputError('Bad input', { errors }); // aquí se mostratán los errors generados arriba.
            }
        }
    }
}