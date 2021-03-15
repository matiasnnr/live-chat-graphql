const { User } = require('../models');
const bcrypt = require('bcryptjs');

module.exports = {
    Query: {
        getUsers: async () => {
            try {
                const users = await User.findAll();

                return users;
            } catch (error) {
                console.log(error);
            }
        },
    },
    Mutation: {
        // register: async (parent, args, context, info) => {
        register: async (_, args) => {
            let { username, email, password, confirmPassword } = args;

            try {
                // TODO: Validate input data

                // TODO: Check if username / email exists

                // Hash password
                password = await bcrypt.hash(password, 6);

                // Create user
                const user = await User.create({ username, email, password });

                // Return user
                return user;
            } catch (error) {
                console.log(error);
                throw error;
            }
        }
    }
}