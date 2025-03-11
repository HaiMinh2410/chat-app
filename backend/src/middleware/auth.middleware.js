import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    // 1️⃣ Lấy token từ cookie
    const token = req.cookies.jwt;

    // 2️⃣ Kiểm tra nếu không có token
    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No Token Provided" });
    }

    // 3️⃣ Giải mã token để lấy userId
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized - Invalid Token" });
    }

    // 4️⃣ Tìm user trong database
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 5️⃣ Lưu user vào request để sử dụng trong các middleware tiếp theo
    req.user = user;

    // 6️⃣ Tiếp tục xử lý request
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
