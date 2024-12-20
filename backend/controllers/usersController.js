const {validationResult} = require("express-validator");
const UserModel = require("../models/User");
const {hashedPassword, createToken,comparePassword} = require("../services/authServices");

// @route POST /api/register
// @access Public
// @desc Create user and return a token
module.exports.register = async (req, res) => {
    const errors = validationResult(req);
    if(errors.isEmpty()){
        const {name, email, password} = req.body;
        try {
            const emailExist = await UserModel.findOne({email});
            if(!emailExist) {
                const hashed = await hashedPassword(password);
                const user = await UserModel.create({
                    name,
                    email,
                    password: hashed
                });
                const token = createToken({id: user._id, name: user.name});
                return res.status(201).json({msg: 'Tài khoản của bạn đã được tạo thành công!', token});
            } else {
                // email already taken
                return res.status(400).json({errors: [{msg: `${email} đã có sẵn`, param: 'email'}]})
            }
        } catch (error) {
            console.log(error.message);
            return res.status(500).json("lỗi máy chủ!");
        }
    } else {
        // validations failed
        return res.status(400).json({errors: errors.array()})
    }
}

// @route POST /api/login
// @access Public
// @desc Login user and return a token

module.exports.login = async (req, res) => {
     const {email, password} = req.body;
     const errors = validationResult(req);
     if(errors.isEmpty()) {
         try {
             const user = await UserModel.findOne({email});
             if(user) {
                  if(await comparePassword(password, user.password)) {
                     const token = createToken({id: user._id, name: user.name});
                     if(user.admin) {
                        return res.status(201).json({token, admin: true});
                     } else {
                        return res.status(201).json({token, admin: false});
                     }
                  } else {
                      return res.status(400).json({errors: [{msg: 'Mật khẩu không đúng', param: 'password'}]})
                  }
             } else {
                 return res.status(400).json({errors: [{msg: `${email} không được tìm thấy`, param: 'email'}]});
             }
         } catch (error) {
             console.log(error.message)
             return res.status(500).json('Lỗi máy chủ!');
         }
     } else {
        //  validations failed
        return res.status(400).json({errors: errors.array()})
     }
}