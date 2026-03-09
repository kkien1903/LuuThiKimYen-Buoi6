var express = require('express');
let slugify = require('slugify');
var router = express.Router();
let modelProduct = require('../schemas/products');
let { checkLogin, checkRole, optionalAuth } = require('../utils/authHandler');

/* 
  QUYỀN TRUY CẬP PRODUCTS:
  - GET (tất cả user - không cần đăng nhập): optionalAuth
  - CREATE, UPDATE: checkLogin + checkRole("ADMIN", "MODERATOR")
  - DELETE: checkLogin + checkRole("ADMIN")
*/

// GET all products - Public (không cần đăng nhập)
router.get('/', optionalAuth, async function (req, res, next) {
  try {
    let data = await modelProduct.find({});
    let queries = req.query;
    let titleQ = queries.title ? queries.title : '';
    let maxPrice = queries.maxPrice ? queries.maxPrice : 1E4;
    let minPrice = queries.minPrice ? queries.minPrice : 0;
    let limit = queries.limit ? parseInt(queries.limit) : 5;
    let page = queries.page ? parseInt(queries.page) : 1;
    
    let result = data.filter(function (e) {
      return (!e.isDeleted) && e.price >= minPrice
        && e.price <= maxPrice && e.title.toLowerCase().includes(titleQ.toLowerCase());
    });
    
    let total = result.length;
    result = result.splice(limit * (page - 1), limit);
    
    res.json({
      success: true,
      data: result,
      pagination: {
        page: page,
        limit: limit,
        total: total
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Lỗi khi lấy danh sách sản phẩm"
    });
  }
});

// GET product by ID - Public (không cần đăng nhập)
router.get('/:id', optionalAuth, async function (req, res, next) {
  try {
    let id = req.params.id;
    let result = await modelProduct.findById(id);
    if (result && (!result.isDeleted)) {
      res.json({
        success: true,
        data: result
      });
    } else {
      res.status(404).json({
        success: false,
        message: "Không tìm thấy sản phẩm"
      });
    }
  } catch (error) {
    res.status(404).json({
      success: false,
      message: "ID không hợp lệ"
    });
  }
});

// POST - Create product (ADMIN, MODERATOR)
router.post('/', checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let newObj = new modelProduct({
      title: req.body.title,
      slug: slugify(req.body.title, {
        replacement: '-',
        remove: undefined,
        locale: 'vi',
        trim: true
      }),
      price: req.body.price,
      description: req.body.description,
      category: req.body.category,
      images: req.body.images
    });
    await newObj.save();
    res.status(201).json({
      success: true,
      message: "Tạo sản phẩm thành công",
      data: newObj
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Lỗi khi tạo sản phẩm: " + error.message
    });
  }
});

// PUT - Update product (ADMIN, MODERATOR)
router.put('/:id', checkLogin, checkRole("ADMIN", "MODERATOR"), async function (req, res, next) {
  try {
    let id = req.params.id;
    
    // Nếu có cập nhật title, cập nhật luôn slug
    if (req.body.title) {
      req.body.slug = slugify(req.body.title, {
        replacement: '-',
        remove: undefined,
        locale: 'vi',
        trim: true
      });
    }
    
    let result = await modelProduct.findByIdAndUpdate(
      id, 
      req.body, 
      { new: true }
    );
    
    if (!result) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy sản phẩm"
      });
    }
    
    res.json({
      success: true,
      message: "Cập nhật sản phẩm thành công",
      data: result
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Lỗi khi cập nhật sản phẩm: " + error.message
    });
  }
});

// DELETE - Delete product (Chỉ ADMIN)
router.delete('/:id', checkLogin, checkRole("ADMIN"), async function (req, res, next) {
  try {
    let id = req.params.id;
    let result = await modelProduct.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    
    if (!result) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy sản phẩm"
      });
    }
    
    res.json({
      success: true,
      message: "Xóa sản phẩm thành công",
      data: result
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Lỗi khi xóa sản phẩm: " + error.message
    });
  }
});

module.exports = router;
