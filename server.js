//Node.js 10.14.0
//Plain Javascript and Node.js is supported
// html/css is not supported here 
// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();

// استخدام body-parser لتحليل JSON
app.use(bodyParser.json());

// الاتصال بقاعدة البيانات (يجب تعديل رابط الاتصال حسب بيئتك)
mongoose.connect('mongodb://localhost:27017/myapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('تم الاتصال بقاعدة البيانات بنجاح'))
  .catch(err => console.error('خطأ في الاتصال بقاعدة البيانات:', err));

// تعريف نموذج المستخدم
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true  // التأكد من عدم تكرار البريد الإلكتروني
    },
    password: {
        type: String,
        required: true
    }
});

const User = mongoose.model('User', UserSchema);

/**
 * إنشاء حساب جديد
 */
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // التحقق من وجود بيانات الإدخال
        if (!email || !password) {
            return res.status(400).json({ error: 'يجب إدخال البريد الإلكتروني وكلمة المرور' });
        }
        
        // التحقق مما إذا كان المستخدم موجود مسبقاً
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });
        }
        
        // تشفير كلمة المرور باستخدام bcrypt
        const saltRounds = 10; // يمكن زيادة قيمة saltRounds لمستوى أمان أعلى
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // إنشاء المستخدم وحفظه في قاعدة البيانات
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        
        res.status(201).json({ message: 'تم إنشاء الحساب بنجاح' });
    } catch (error) {
        console.error('خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
    }
});

/**
 * تسجيل الدخول
 */
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // التحقق من وجود بيانات الإدخال
        if (!email || !password) {
            return res.status(400).json({ error: 'يجب إدخال البريد الإلكتروني وكلمة المرور' });
        }
        
        // البحث عن المستخدم في قاعدة البيانات
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'البريد الإلكتروني غير موجود' });
        }
        
        // مقارنة كلمة المرور المدخلة مع كلمة المرور المخزنة بعد التشفير
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'كلمة المرور غير صحيحة' });
        }
        
        // إنشاء رمز JWT يحتوي على بيانات المستخدم (يجب تخزين المفتاح السري في متغير بيئي في الإنتاج)
        const token = jwt.sign(
            { id: user._id, email: user.email },
            'secretKey', // يجب استبدال 'secretKey' بمفتاح قوي وآمن من متغيرات البيئة
            { expiresIn: '1h' } // مدة صلاحية الرمز
        );
        
        res.status(200).json({ message: 'تم تسجيل الدخول بنجاح', token });
    } catch (error) {
        console.error('خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
    }
});

// تشغيل الخادم على المنفذ 3000
app.listen(3000, () => console.log('الخادم يعمل على المنفذ 3000'));