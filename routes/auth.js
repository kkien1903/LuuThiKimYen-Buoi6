var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
let jwt = require('jsonwebtoken');
let { checkLogin } = require('../utils/authHandler');
let bcrypt = require('bcrypt');
let userModel = require('../schemas/users');

// POST /auth/register - Đăng ký tài khoản mới
router.post('/register', async function (req, res, next) {
  try {
    let newUser = await userController.CreateAnUser(
      req.body.username,
      req.body.password,
      req.body.email,
      "69a5462f086d74c9e772b804" // Default role ID cho user thường
    );
    res.status(201).json({
      success: true,
      message: "Đăng ký thành công"
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Đăng ký thất bại: " + error.message
    });
  }
});

// POST /auth/login - Đăng nhập
router.post('/login', async function (req, res, next) {
  try {
    let { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng cung cấp username và password"
      });
    }
    
    // Tìm user theo username
    let user = await userModel.findOne({ 
      username: username,
      isDeleted: false 
    }).populate('role');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Thông tin đăng nhập không chính xác"
      });
    }
    
    // Kiểm tra password
    let isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Thông tin đăng nhập không chính xác"
      });
    }
    
    // Cập nhật loginCount
    await userModel.updateOne(
      { _id: user._id },
      { $inc: { loginCount: 1 } }
    );
    
    // Tạo token
    let token = jwt.sign({
      id: user._id,
      role: user.role ? user.role.name : null
    }, 'secret', {
      expiresIn: '1h'
    });
    
    res.cookie("token", token, {
      maxAge: 60 * 60 * 1000,
      httpOnly: true
    });
    
    res.json({
      success: true,
      message: "Đăng nhập thành công",
      token: token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role ? user.role.name : null
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi đăng nhập: " + error.message
    });
  }
});

// GET /auth/me - Lấy thông tin user hiện tại
router.get('/me', checkLogin, async function (req, res, next) {
  try {
    let user = await userModel
      .findById(req.userId)
      .populate({
        path: 'role',
        select: 'name description'
      })
      .select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy user"
      });
    }
    
    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi khi lấy thông tin user"
    });
  }
});

// POST /auth/logout - Đăng xuất
router.post('/logout', checkLogin, function (req, res, next) {
  res.cookie('token', null, {
    maxAge: 0,
    httpOnly: true
  });
  res.json({
    success: true,
    message: "Đăng xuất thành công"
  });
});

module.exports = router;
