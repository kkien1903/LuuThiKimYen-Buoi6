var express = require("express");
var router = express.Router();
let { postUserValidator, validateResult } = require('../utils/validatorHandler');
let userController = require('../controllers/users');
let { checkLogin, checkRole } = require('../utils/authHandler');
let userModel = require("../schemas/users");
let bcrypt = require('bcrypt');

/*
  QUYỀN TRUY CẬP USERS:
  - ADMIN: Full quyền (CRUD tất cả users)
  - MODERATOR: Chỉ Read All (GET)
  - User thường: Chỉ xem/sửa thông tin của chính mình
*/

// GET all users - ADMIN & MODERATOR có quyền
router.get("/", checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let users = await userModel
      .find({ isDeleted: false })
      .populate({
        'path': 'role',
        'select': "name description"
      })
      .select('-password'); // Không trả về password
    
    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi khi lấy danh sách users"
    });
  }
});

// GET user by ID - ADMIN, MODERATOR hoặc chính user đó
router.get("/:id", checkLogin, async function (req, res, next) {
  try {
    let requestedId = req.params.id;
    let currentUserId = req.userId;
    let currentRole = req.userRole;

    // Kiểm tra quyền: Admin/Mod xem tất cả, user thường chỉ xem của mình
    if (currentRole !== "ADMIN" && currentRole !== "MODERATOR" && requestedId !== currentUserId) {
      return res.status(403).json({
        success: false,
        message: "Bạn không có quyền xem thông tin người dùng khác"
      });
    }

    let result = await userModel
      .findOne({ _id: requestedId, isDeleted: false })
      .populate({
        'path': 'role',
        'select': "name description"
      })
      .select('-password');

    if (result) {
      res.json({
        success: true,
        data: result
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Không tìm thấy user"
      });
    }
  } catch (error) {
    res.status(404).json({
      success: false,
      message: "ID không hợp lệ"
    });
  }
});

// POST - Create user (Chỉ ADMIN)
router.post("/", checkLogin, checkRole("ADMIN"), postUserValidator, validateResult,
  async function (req, res, next) {
    try {
      let newItem = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        req.body.role
      );
      
      let saved = await userModel
        .findById(newItem._id)
        .populate({
          'path': 'role',
          'select': "name description"
        })
        .select('-password');
      
      res.status(201).json({
        success: true,
        message: "Tạo user thành công",
        data: saved
      });
    } catch (err) {
      res.status(400).json({
        success: false,
        message: err.message
      });
    }
  }
);

// PUT - Update user (Chỉ ADMIN)
router.put("/:id", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    
    // Không cho phép cập nhật password qua route này
    if (req.body.password) {
      delete req.body.password;
    }
    
    let updatedItem = await userModel.findByIdAndUpdate(
      id,
      req.body,
      { new: true }
    ).populate({
      'path': 'role',
      'select': "name description"
    }).select('-password');

    if (!updatedItem) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy user"
      });
    }

    res.json({
      success: true,
      message: "Cập nhật user thành công",
      data: updatedItem
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

// DELETE - Delete user (Chỉ ADMIN)
router.delete("/:id", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    
    // Không cho phép xóa chính mình
    if (id === req.userId) {
      return res.status(400).json({
        success: false,
        message: "Bạn không thể xóa chính mình"
      });
    }
    
    let updatedItem = await userModel.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    
    if (!updatedItem) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy user"
      });
    }
    
    res.json({
      success: true,
      message: "Xóa user thành công"
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

// POST - Đổi mật khẩu (User đã đăng nhập)
router.post("/change-password", checkLogin, async function (req, res, next) {
  try {
    let { oldPassword, newPassword } = req.body;
    
    // Validate input
    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng cung cấp mật khẩu cũ và mật khẩu mới"
      });
    }
    
    // Kiểm tra độ dài mật khẩu mới
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Mật khẩu mới phải có ít nhất 6 ký tự"
      });
    }
    
    // Lấy user hiện tại với password
    let user = await userModel.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy user"
      });
    }
    
    // Kiểm tra mật khẩu cũ
    let isMatch = bcrypt.compareSync(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Mật khẩu cũ không chính xác"
      });
    }
    
    // Hash mật khẩu mới
    let salt = bcrypt.genSaltSync(10);
    let hashedPassword = bcrypt.hashSync(newPassword, salt);
    
    // Cập nhật mật khẩu (dùng updateOne để tránh trigger pre-save)
    await userModel.updateOne(
      { _id: req.userId },
      { password: hashedPassword }
    );
    
    res.json({
      success: true,
      message: "Đổi mật khẩu thành công"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi khi đổi mật khẩu: " + error.message
    });
  }
});

module.exports = router;
