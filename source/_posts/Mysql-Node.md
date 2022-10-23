---
title: Mysql + Node
date: 2022-10-23 22:49:16
tags:
---

# MySQL

## 语句&字句

### 查询语句

1. 查询所有数据

```
select * from 表名
```

2. 查询相对应的数据

```
select x,y from 表名
```

3. 例子：

```
-- 通过 * 把users表中所以的数据查询出来
select * from users

-- 从users 表中把username 和 password 对应的数据查询出来
 select username,password from users
```

### 插入语句

INSERT INTO 语句用于向数据表中插入新的数据行

1. 语法

```
insert into 表名[属性1，属性2，...] values('x1','x2',...)
```

2. 例子

```
-- 向 users 表中，插入一条 username 为 tony stark，password 为 098123 的用户数据
 insert into users(username,password) values ('tony stark','098123')

```

### 更新语句

1. update 语句用于修改表中的数据

```
1. update 指定要更新哪个表的数据
2. set 指定列对呀的新值
3. where 指定更新条件

update 表名 set 列名=新值 where 列名=某值
```

2. 例子

```
-- 把 users 表中 id 为 4 的用户密码，更新为 888888
 update users set password='888888' where id=4

-- 更新多列 ：把 users 表中 id 为 2 的用户密码和用户状态，分别更新为 admin123 和 1
 update users set password='admin123',status=1 where id=2

```

### 删除语句

1. 删除某数据

```
delete from 表名  where  列名=某值
```

2. 例子

```
- 从 users 表中，删除 id 为 4 的用户
delete from users where id=4
```

### where 语句

1.  where 子句用于限定**列选择的标准**。在 **SELECT、UPDATE、DELET**E 语句中，皆可使用 WHERE 子句来限定选择的标准
2.  可在 where 子句中使用的运算符

![image.png](https://cdn.nlark.com/yuque/0/2022/png/32607841/1664721898333-4112585a-d144-4193-a62c-13ec73410a84.png#clientId=uee7b89bc-8a7f-4&crop=0&crop=0&crop=1&crop=1&errorMessage=unknown%20error&from=paste&height=267&id=u28f9fed9&margin=%5Bobject%20Object%5D&name=image.png&originHeight=334&originWidth=903&originalType=binary&ratio=1&rotation=0&showTitle=false&size=29638&status=error&style=none&taskId=ud823cbdb-084e-4d49-a879-ebc9bb7b216&title=&width=722.4)

### AND 和 OR 运算符

AND 和 OR 可在 WHERE 子语句中把两个或多个条件结合起来。 AND 表示必须同时满足多个条件，相当于 JavaScript 中的 && 运算符，例如 if (a !== 10 && a !== 20) OR 表示只要满足任意一个条件即可，相当于 JavaScript 中的 || 运算符，例如 if(a !== 10 || a !== 20)  
例子：

```
-- 使用 AND 来显示所有 status 为 0，并且 id 小于 3 的用户
select * from users where status=0 and id<3
-- 使用 OR 来显示所有 status 为 1，或者 username 为 zs 的用户
 select * from users where status=0 or username=' 张三'
```

### ORDER BY 子句

ORDER BY 语句用于根据指定的列对结果集进行排序。
ORDER BY 语句默认按照升序对记录进行排序。
如果您希望按照降序对记录进行排序，可以使用 DESC 关键字

```
-- 对 users 表中的数据，按照 status 字段进行升序排序
 select * from users order by status
-- 对 users 表中的数据，按照 id 字段进行降序排序 desc表示降序 asc表示升序（默认）
 select * from users order by id desc
-- 对 users 表中的数据，先按照 status 字段进行降序排序，再按照 username 的字母顺序，进行升序排序
 select * from users order by status desc,username
```

### COUNT(\*) 函数 &as 设置列别名

COUNT(\*) 函数用于返回查询结果的总数据条数 语法如下：

```
select count(*) from 表名


--  查询 users 表中 status 为 0 的总数据条数
  select count(*) from users where status=0
 -- 使用as关键字给列取别名
  select count(*) as total from users where status=0
  select username as uname,password as upwd from users
```

## 在项目中操作数据库

### 安装与配置 mysql

1. 下载第三方配置包

```
npm i mysql
```

2. 配置 mysql 模块

```
// 导入mysql模块
const mysql = require('mysql')
// 建立MySQL 数据库的连接关系
const db = mysql.createPool({
    host: '127.0.0.1',  //数据库的ip地址
    user: 'root',   //数据库的账号
    password: 'admin123',   //登陆数据库的密码
    database: 'my_db_01'   //指定操作的数据库
})
```

3. 测试 mysql 是否能正式工作

```
db.query('select 1',(err,results)=>{
    // mysql模块工作期间报错
    if(err) return console.log(err,message);
    // 能够成功的执行语句
    console.log(results);
})
```

### 查询数据

查询 users 表中所有的数据

```
const sqlStr ='select * from users'
db.query(sqlStr,(err,results)=>{
     // 查询数据失败
     if(err) return console.log(err,message);
     // 查询成功
     // 如果执行的是select 查询语句 则执行的结果是数组
     console.log(results);
})
```

### 插入数据

1. 向 users 表中新增数据， 其中 username 为 Spider-Man，password 为 pcc321。

```
const user={username:'Spider-Man',password:'pcc123'}
// 定义待执行的SQL语句
const sqlStr='insert into users (username,password) values (?,?)'
db.query(sqlStr,[user.username,user.password],(err,result)=>{
    // 失败
    if(err) return console.log(err.message);
    // 成功
    // 注意：如果执行的是insert into 语句，则result是一个对象
    // 可以通过affectedRows属性判断是否插入数据成功
   if(result.affectedRows===1){
    console.log('插入数据成功');
   }
})
```

2. **插入数据的便捷方式**

```
const user={username:'Spider-Man2',password:'pcc4321'}
// 定义待执行的SQL语句
const sqlStr='insert into users set ?'
db.query(sqlStr,user,(err,result)=>{

    if(err) return console.log(err.message);

   if(result.affectedRows===1){
    console.log('插入数据成功');
   }
})
```

### 更新数据

1. 方式一

```
const user = { id: 8, username: 'aaa', password: '00021' }
const sqlStr = 'update users set username=?,password = ? where id=?'
db.query(sqlStr,[user.username,user.password,user.id],(err,result)=>{
    if(err) return console.log(err.message);
    // 注意：执行力update语句之后，执行的结果，也是一个对象，可以通过affectedRows判断是否成功
    if(result.affectedRows===1){
        console.log('更新数据成功');
       }
})
```

2. **方式二**

```
const user = { id: 3, username: '小栈', password: '012021' }
const sqlStr = 'update users set ? where id=?'
db.query(sqlStr,[user,user.id],(err,result)=>{
    if(err) return console.log(err.message);
    // 注意：执行update语句之后，执行的结果，也是一个对象，可以通过affectedRows判断是否成功
    if(result.affectedRows===1){
        console.log('更新数据成功');
       }
})
```

### 删除数据

1.  在删除数据时，推荐根据 id 这样的唯一标识，来删除对应的数据

```
const sqlStr='delete from users where id=?'
db.query(sqlStr,5,(err,result)=>{
    if(err) return console.log(err.message);
    // 注意：执行delete语句之后，执行的结果，也是一个对象，可以通过affectedRows判断是否成功
    if(result.affectedRows===1){
        console.log('删除数据成功');
       }
})
```

2.  推荐使用标记删除的形式，来模拟删除的动作。 所谓的**标记删除**，就是在表中设置类似于 status 这样的状态字段，来标记当前这条数据是否被删除。 当用户执行了删除的动作时，我们并没有执行 DELETE 语句把数据删除掉，而是执行了 UPDATE 语句，将这条数据对应 的 status 字段标记为删除即可

```
const sqlStr='update users set status=? where id=?'
db.query(sqlStr,[1,8],(err,result)=>{
    if(err) return console.log(err.message);
    // 注意：执行delete语句之后，执行的结果，也是一个对象，可以通过affectedRows判断是否成功
    if(result.affectedRows===1){
        console.log('标记删除成功');
       }
})
```

# 前后端身份认证

## Jwt 认证机制

工作原理：
:::warning
用户的信息通过 Token 字符串的形式，保存在客户端浏览器中。服务器通过还原 Token 字符串的形式来认证用户的身份  
:::
组成部分：
:::warning
分别是 Header（头部）、Payload（有效荷载）、Signature（签名）  
 Payload 部分才是真正的用户信息，它是用户信息经过加密之后生成的字符串。
Header 和 Signature 是安全性相关的部分，只是为了保证 Token 的安全性  
:::

使用方式
:::warning
客户端收到服务器返回的 JWT 之后，通常会将它**储存在 localStorage 或 sessionStorage** 中

此后，客户端每次与服务器通信，都要带上这个 JWT 的字符串，从而进行身份认证。推荐的做法是把 JWT 放在 **HTTP 请求头的 Authorization** 字段中  
:::
在 Express 中使用 JWT

1. 按照相关的包

```
npm i jsonwebtoken express-jwt

jsonwebtoken 用于生成JWT字符串
express-jwt t 用于将 JWT 字符串解析还原成 JSON 对象
```

2. 导入【哪个文件需要就在该文件导入】

```
const jwt = require('jsonwebtoken')
const expressJWT = require('express-jwt')
```

3.  定义 secret 密钥 【可以单独一个文件定义导出再在需要的文件中引入】
    :::warning
    为了保证 JWT 字符串的安全性，防止 JWT 字符串在网络传输过程中被别人破解，我们需要专门定义一个用于加密和解密 的 secret 密钥：
    ① 当生成 JWT 字符串的时候，需要使用 secret 密钥对用户的信息进行加密，最终得到加密好的 JWT 字符串
    ② 当把 JWT 字符串解析还原成 JSON 对象的时候，需要使用 secret 密钥进行解密
    :::

```
const secretKey = 'kunkun No1 ^_^'
```

4.  在登录成功后生成 JWT 字符串

调用 jsonwebtoken 包提供的** sign() 方法，将用户的信息加密成 JWT 字符串**，响应给客户端：

```
// 登录接口
app.post('/api/login', function (req, res) {
  // 将 req.body 请求体中的数据，转存为 userinfo 常量
  const userinfo = req.body
  // 登录失败
  if (userinfo.username !== 'admin' || userinfo.password !== '000000') {
    return res.send({
      status: 400,
      message: '登录失败！',
    })
  }
  // 登录成功
  // TODO_03：在登录成功之后，调用 jwt.sign() 方法生成 JWT 字符串。并通过 token 属性发送给客户端
  // 参数1：用户的信息对象
  // 参数2：加密的秘钥
  // 参数3：配置对象，可以配置当前 token 的有效期
  // 记住：千万不要把密码加密到 token 字符中
  const tokenStr = jwt.sign({ username: userinfo.username }, secretKey, { expiresIn: '30s' })
  res.send({
    status: 200,
    message: '登录成功！',
    token: 'Bearer '+tokenStr, // 要发送给客户端的 token 字符串
  })
})
```

5.  将 JWT 字符串还原为 JSON 对象 【main.js:服务器的入口地址】

:::warning
这里注意一个问题，以后测试接口，接口**除了带/api 开头的，都要在请求头加上**：**Authorization:Bearer<token>**
:::

```
// 注意：只要配置成功了 express-jwt 这个中间件，就可以把解析出来的用户信息，挂载到 req.user 属性上
app.use(expressJWT({ secret: secretKey }).unless({ path: [/^\/api\//] }))
```

6. ** 使用 req.user 获取用户信息** 【**这里是获取登陆的接口的用户信息**】
   :::warning
   当 express-jwt 这个中间件配置成功之后，即可在那些有权限的接口中，使用** req.user 对象，来访问从 JWT 字符串 中解析出来的用户信息了**，示例代码如下  
   :::

```
// 这是一个有权限的 API 接口
app.get('/admin/getinfo', function (req, res) {
  // TODO_05：使用 req.user 获取用户信息，并使用 data 属性将用户信息发送给客户端
  console.log(req.user)
  res.send({
    status: 200,
    message: '获取用户信息成功！',
    data: req.user, // 要发送给客户端的用户信息
  })
})
```

7.  捕获解析 JWT 失败后产生的错误 【main.js:服务器的入口地址】
    :::warning
    当使用 express-jwt 解析 Token 字符串时，如果客户端发送过来的 Token 字符串过期或不合法，会产生一个解析失败 的错误，影响项目的正常运行。我们可以通过 Express 的错误中间件，捕获这个错误并进行相关的处理，示例代码如下
    :::

```
// TODO_06：使用全局错误处理中间件，捕获解析 JWT 失败后产生的错误
app.use((err, req, res, next) => {
  // 这次错误是由 token 解析失败导致的
  if (err.name === 'UnauthorizedError') {
    return res.send({
      status: 401,
      message: '无效的token',
    })
  }
  res.send({
    status: 500,
    message: '未知的错误',
  })
})
```

## 密码操作

### 对密码进行加密处理

> 为了保证密码的安全性，不建议在数据库以 明文 的形式保存用户密码，推荐对密码进行 **加密 存储 **

> 在当前项目中，使用 `**bcryptjs**` 对用户密码进行加密，
> 优点： 加密之后的密码，**无法被逆向破解 **
> 同一明文密码多次加密，得到的**加密结果各不相同**，保证了安全性

运用场景：**注册接口插入该密码之前对密码进行加密**

1.  运行如下命令，安装指定版本的 bcryptjs

```
npm i bcryptjs@2.4.3
```

2. 操作该路由模块 导入 bcryptjs

```
const bcrypt = require('bcryptjs')
```

3.  在注册用户的处理函数中，确认用户名可用之后，调用 `**bcrypt.hashSync**`(明文密码, 随机盐的 长度) 方法，对用户的密码进行加密处理

```
// 对用户的密码,进行 bcrype 加密，返回值是加密之后的密码字符串
userinfo.password = bcrypt.hashSync(userinfo.password, 10)
```

### 更新密码处理

> 调用` **bcrypt.compareSync**`(用户提交的密码, 数据库中的密码) 方法比较密码是 否一致
>
> 返回值是布尔值（true 一致、false 不一致）

```javascript
//
.... 上方是根据id查询到相应的账户， results[0].password 是获取到的密码
// 判断提交的旧密码是否正确
const compareResult = bcrypt.compareSync(req.body.oldPwd, results[0].password)
if (!compareResult) return res.cc('旧密码错误')

// 定义更新用户密码的 SQL 语句
const sql = `update en_users set password=? where id=?`
// 对新密码进行 bcrypt 加密处理
const newPwd = bcrypt.hashSync(req.body.newPwd, 10)
// 执行 SQL 语句，根据 id 更新用户的密码
db.query(sql, [newPwd, req.user.id], (err, results) => {
  // SQL 语句执行失败
  if (err) return res.cc(err)
  // SQL 语句执行成功，但是影响行数不等于 1
  if (results.affectedRows !== 1) return res.cc('更新密码失败！')
  // 更新密码成功
  res.cc('更新密码成功！', 0)
})
```

## 优化表单数据验证

> 表单验证的原则：前端验证为辅，后端验证为主，后端**永远不要相信**前端提交过来的**任何内容**

单纯的使用 if...else... 的形式对数据合法性进行验证，效率低下、出错率高、维护性差。因此， 推荐使用**第三方数据验证模块**，来降低出错率、提高验证的效率与可维护性，让**后端程序员把更多的精 力放在核心业务逻辑的处理上 **

1.  安装 @hapi/joi 包，为表单中携带的每个数据项，定义验证规则：

```javascript
npm install @hapi/joi@17.1.0
```

2.  安装 @escook/express-joi 中间件，来实现自动对表单数据进行验证的功能

```javascript
npm i @escook/express-joi
```

3.  新建 /schema/user.js 用户信息验证规则模块，并初始化代码如下

```javascript
const joi = require('@hapi/joi')
/**
* string() 值必须是字符串
* alphanum() 值只能是包含 a-zA-Z0-9 的字符串
* min(length) 最小长度
* max(length) 最大长度
* required() 值是必填项，不能为 undefined
* pattern(正则表达式) 值必须符合正则表达式的规则
 // 使用 joi.not(joi.ref('oldPwd')).concat(password) 规则，验证 req.body.newPwd 的值
        // 解读：
        // 1. joi.ref('oldPwd') 表示 newPwd 的值必须和 oldPwd 的值保持一致
        // 2. joi.not(joi.ref('oldPwd')) 表示 newPwd 的值不能等于 oldPwd 的值
        // 3. .concat() 用于合并 joi.not(joi.ref('oldPwd')) 和 password 这两条验证规则
        // dataUri() 指的是如下格式的字符串数据：
*/
// 用户名的验证规则
const username = joi.string().alphanum().min(1).max(10).required()
// 密码的验证规则
const password = joi
	.string()
	.pattern(/^[\S]{6,12}$/)
	.required()
// 注册和登录表单的验证规则对象
exports.reg_login_schema = {
	// 表示需要对 req.body 中的数据进行验证
	body: {
		username,
		password,
	},
}
```

4.  修改 /router/user.js 中的代码如下：

```javascript
// 1. 导入验证表单数据的中间件
const expressJoi = require('@escook/express-joi')
// 2. 导入需要的验证规则对象
const { reg_login_schema } = require('../schema/user')

router.post('/reguser', expressJoi(reg_login_schema), userHandler.regUser)
```

5.  在 app.js 的全局错误级别中间件中，捕获验证失败的错误，并把验证失败的结果响应给客户 端

```javascript
const joi = require('joi')
// 错误中间件
app.use(function (err, req, res, next) {
	// 数据验证失败
	if (err instanceof joi.ValidationError) return res.cc(err)
	// 未知错误
	res.cc(err)
})
```

# \*\*\*node 接口理解

> 1. node.js 识别到相关的接口，接收到来自客户端的相关参数，主要是请求体的参数
>
> 2. 获取请求体的参数： **req.body **拿到的是一个包含请求的参数对象，取出来是 req.body.xxx
>
>    如果已经登录了，并且是 token 登录的，那么获取用户信息是** req.user**
>    \*\* ** 获取 url 的参数：**req.params req.query\*\*
>
> 3. 对获取到的用户参数，根据条件，参数可以存储到数据库中，或者是数据库的参数=用户参数时，进行某些操作----------即参数在数据库中增删查改
>
> 4. 查询的时候，可将数据库的数据发送给客户端；增加的时候，存入数据库中，同时告知客户端插入成功；修改和删除同增加
