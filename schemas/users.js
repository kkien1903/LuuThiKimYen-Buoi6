const mongoose = require("mongoose");
let bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, "Username is required"],
            unique: true
        },

        password: {
            type: String,
            required: [true, "Password is required"]
        },

        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            lowercase: true,
            match: [/^\S+@\S+\.\S+$/, "Invalid email format"]
        },

        fullName: {
            type: String,
            default: ""
        },

        avatarUrl: {
            type: String,
            default: "https://i.sstatic.net/l60Hf.png"
        },

        status: {
            type: Boolean,
            default: false
        },

        role: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "role",
            required: true
        },

        loginCount: {
            type: Number,
            default: 0,
            min: [0, "Login count cannot be negative"]
        },
        isDeleted: {
            type: Boolean,
            default: false
        }
    },
    {
        timestamps: true
    }
);

userSchema.index({
    username: 1,
    email: 1
});

// Chỉ hash password khi password được thay đổi (không hash lại nếu đã hash)
userSchema.pre('save', function(next) {
    // Chỉ hash password nếu nó được modified
    if (!this.isModified('password')) {
        return next();
    }
    
    // Kiểm tra xem password đã được hash chưa (bcrypt hash bắt đầu với $2)
    if (this.password && !this.password.startsWith('$2')) {
        let salt = bcrypt.genSaltSync(10);
        this.password = bcrypt.hashSync(this.password, salt);
    }
    next();
});

// Method để so sánh password
userSchema.methods.comparePassword = function(candidatePassword) {
    return bcrypt.compareSync(candidatePassword, this.password);
};

module.exports = mongoose.model("user", userSchema);
