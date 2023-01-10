const bcrypt = require('bcrypt');
const jwt  = require('jsonwebtoken');

const { APP_SECRET } = require('../config');

//Utility functions
exports.GenerateSalt = async() => {
        return await bcrypt.getSalt();
}

exports.GeneratePassword = async (password, salt) => {
        return await bcrypt.hash(password, salt);
};


exports.ValidatePassword = async (enteredPassword, savedPassword, salt) => {
        return await this.GeneratePassword(enteredPassword, salt) === savedPassword;
};

exports.GenerateSignature = async (payload) => {
        return await jwt.sign(payload, APP_SECRET, { expiresIn: '1d'} )
}, 

exports.ValidateSignature  = async(req) => {

        const signature = req.get('Authorization');
        
        if(signature){
            const payload = await jwt.verify(signature.split(' ')[1], APP_SECRET);
            req.user = payload;
            return true;
        }

        return false
};

exports.FormateData = (data) => {
        if(data){
            return { data }
        }else{
            throw new Error('Data Not found!')
        }
}
