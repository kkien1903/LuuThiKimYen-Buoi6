var express = require("express");
var router = express.Router();
let { checkLogin, checkRole } = require('../utils/authHandler');
let roleModel = require("../schemas/roles");

/*
  QUYỀN TRUY CẬP ROLES:
  - ADMIN: Full quyền (CRUD tất cả roles)
  - MODERATOR: Chỉ Read All (GET)
*/

// GET all roles - ADMIN & MODERATOR có quyền
router.get("/", checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let roles = await roleModel.find({ isDeleted: false });
    res.json({
      success: true,
      data: roles
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi khi lấy danh sách roles"
    });
  }
});

// GET role by ID - ADMIN & MODERATOR có quyền
router.get("/:id", checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let result = await roleModel.findOne({ _id: req.params.id, isDeleted: false });
    if (result) {
      res.json({
        success: true,
        data: result
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Không tìm thấy role"
      });
    }
  } catch (error) {
    res.status(404).json({
      success: false,
      message: "ID không hợp lệ"
    });
  }
});

// POST - Create role (Chỉ ADMIN)
router.post("/", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let newItem = new roleModel({
      name: req.body.name,
      description: req.body.description
    });
    await newItem.save();
    res.status(201).json({
      success: true,
      message: "Tạo role thành công",
      data: newItem
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

// PUT - Update role (Chỉ ADMIN)
router.put("/:id", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await roleModel.findByIdAndUpdate(id, req.body, { new: true });
    if (!updatedItem) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy role"
      });
    }
    res.json({
      success: true,
      message: "Cập nhật role thành công",
      data: updatedItem
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

// DELETE - Delete role (Chỉ ADMIN)
router.delete("/:id", checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await roleModel.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    if (!updatedItem) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy role"
      });
    }
    res.json({
      success: true,
      message: "Xóa role thành công"
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
});

module.exports = router;
