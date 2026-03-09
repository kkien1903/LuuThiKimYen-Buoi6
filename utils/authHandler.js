let jwt = require('jsonwebtoken');
let userController = require('../controllers/users');

module.exports = {
    /**
     * Middleware kiểm tra đăng nhập
     * Kiểm tra token từ cookie hoặc header Authorization
     */
    checkLogin: async function (req, res, next) {
        try {
            let token;
            if (req.cookies.token) {
                token = req.cookies.token;
            } else {
                token = req.headers.authorization;
                if (!token || !token.startsWith("Bearer")) {
                    return res.status(401).json({ 
                        success: false,
                        message: "Bạn chưa đăng nhập" 
                    });
                }
                token = token.split(' ')[1];
            }
            
            let result = jwt.verify(token, 'secret');
            if (result && result.exp * 1000 > Date.now()) {
                req.userId = result.id;
                // Lấy thông tin user và role để sử dụng trong các middleware tiếp theo
                let user = await userController.FindUserById(result.id);
                if (!user) {
                    return res.status(401).json({ 
                        success: false,
                        message: "Người dùng không tồn tại" 
                    });
                }
                req.user = user;
                req.userRole = user.role ? user.role.name : null;
                next();
            } else {
                return res.status(401).json({ 
                    success: false,
                    message: "Token đã hết hạn, vui lòng đăng nhập lại" 
                });
            }
        } catch (error) {
            return res.status(401).json({ 
                success: false,
                message: "Token không hợp lệ" 
            });
        }
    },

    /**
     * Middleware kiểm tra quyền theo role
     * @param {...string} requiredRoles - Danh sách các role được phép truy cập
     * Sử dụng: checkRole("ADMIN", "MODERATOR")
     */
    checkRole: function (...requiredRoles) {
        return async function (req, res, next) {
            try {
                let currentRole = req.userRole;
                
                if (!currentRole) {
                    return res.status(403).json({ 
                        success: false,
                        message: "Không thể xác định quyền của bạn" 
                    });
                }

                if (requiredRoles.includes(currentRole)) {
                    next();
                } else {
                    return res.status(403).json({ 
                        success: false,
                        message: "Bạn không có quyền thực hiện thao tác này",
                        required: requiredRoles,
                        current: currentRole
                    });
                }
            } catch (error) {
                return res.status(500).json({ 
                    success: false,
                    message: "Lỗi khi kiểm tra quyền" 
                });
            }
        }
    },

    /**
     * Middleware cho phép truy cập public (không cần đăng nhập)
     * Nếu có token thì vẫn lấy thông tin user
     */
    optionalAuth: async function (req, res, next) {
        try {
            let token;
            if (req.cookies.token) {
                token = req.cookies.token;
            } else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
                token = req.headers.authorization.split(' ')[1];
            }

            if (token) {
                try {
                    let result = jwt.verify(token, 'secret');
                    if (result && result.exp * 1000 > Date.now()) {
                        req.userId = result.id;
                        let user = await userController.FindUserById(result.id);
                        if (user) {
                            req.user = user;
                            req.userRole = user.role ? user.role.name : null;
                        }
                    }
                } catch (e) {
                    // Token không hợp lệ, bỏ qua và tiếp tục như guest
                }
            }
            next();
        } catch (error) {
            next();
        }
    }
};
