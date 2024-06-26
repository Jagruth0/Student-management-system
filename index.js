import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret:process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();


//--------------------STUDENT REQUESTS----------------------

app.get("/register/student", (req, res) => {
  res.render("student/register.ejs");
});

app.get("/login/student", (req, res)=>{
    res.render("student/login.ejs");
});

app.get("/student/announcements", async(req, res) => {
    const user = req.user;
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT name FROM enrollment e JOIN class c ON c.id = e.class_id WHERE e.student_admnno= $1 ORDER BY c.id ASC ", [user.admnno]);
      const name = await db.query("SELECT fname, lname FROM student WHERE admnno = $1", [user.admnno]);
      req.session.username = name.rows[0].fname + " " + name.rows[0].lname;
      res.render("student/announcements.ejs", {classes: result.rows, username: req.session.username, currentAnnoun : true});   
    } catch (err) {
      console.log("Error loading student page: ", err);
    }
  } else {
    res.redirect("/login/student");
  }
});

app.get("/student/attendance", async(req, res)=> {
  if(req.isAuthenticated()){
    try {
      const result = await db.query("SELECT name,attendance,total_days FROM enrollment e JOIN class c ON e.class_id = c.id WHERE e.student_admnno= $1 ORDER BY c.id ASC ",[req.user.admnno]);
      res.render("student/attendance.ejs", {currentAtten: true, username: req.session.username, attend: result.rows});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/student");
  }
});

app.get("/student/results", async(req, res)=> {
  if(req.isAuthenticated()){
    var results = null;
    var testname = null;
    try {
      if(req.session.testname){
        const result = await db.query(`SELECT name,${req.session.testname} FROM enrollment e JOIN class c ON e.class_id = c.id WHERE e.student_admnno= $1 ORDER BY c.id ASC `,[req.user.admnno]);
        results = result.rows;
        testname = req.session.testname;
      }
      req.session.testname = null;
      res.render("student/results.ejs", {currentRes: true, username: req.session.username, grades: results, testname: testname});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/student");
  }
});

app.get("/student/announcements/class" , async(req, res) => {
  if(req.isAuthenticated()){
    try {
      const classname = req.session.classname;
      // req.session.classname = null;
      const result = await db.query("SELECT * FROM class WHERE name = $1",[classname]);
      // console.log(result.rows[0]);
      res.render("student/class_announ.ejs", {announcements: result.rows[0].announcements, classname: classname, currentAnnoun: true, username: req.session.username});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/student");
  }
});

app.get("/student/announcement", async(req, res) => {
  if (req.isAuthenticated()) {
    try {
      const annInd = req.session.annInd;
      const classname = req.session.classname;
      const result = await db.query("SELECT announcements FROM class WHERE name = $1",[classname]);
      res.render("student/announcement_page.ejs", {announcement: result.rows[0].announcements[annInd], username: req.session.username, currentAnnoun: true});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/student");
  }
});

app.get("/logout/student", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login/student");
  });
});


// POST requests

app.post(
  "/login/student",
  passport.authenticate("student-local", {
    successRedirect: "/student/announcements",
    failureRedirect: "/login/student",
  })
);

app.post("/student/announcements/class", (req, res)=>{
  req.session.classname = req.body.class;
  res.redirect("/student/announcements/class");
});

app.post("/student/announcement", (req,res)=>{
  req.session.annInd = parseInt(req.body.index);
  res.redirect("/student/announcement");
});

app.post("/results/exam/student", (req, res)=> {
  req.session.testname = req.body.testname;
  res.redirect("/student/results");
});


//Register new student

app.post("/register/student", async (req, res) => {
  const admnno = req.body.userid;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM student_users WHERE admnno = $1", [
      admnno,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login/student");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO student_users (admnno, password) VALUES ($1, $2) RETURNING *",
            [admnno, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/student/announcements");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


//Passport local Authentication

passport.use(
  "student-local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM student_users WHERE admnno = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);


//-------------TEACHER REQUESTS-----------------------

//GET reqs

app.get("/register/teacher", (req, res) => {
  res.render("teacher/register.ejs");
});

app.get("/login/teacher", (req, res)=>{
    res.render("teacher/login.ejs");
});

app.get("/teacher/announcements", async(req, res) => {
  const user = req.user;
if (req.isAuthenticated()) {
  try {
    const result = await db.query("SELECT name FROM staff s JOIN class c ON c.id = s.class_id WHERE s.teacher_id= $1 ORDER BY c.id ASC ", [user.employee_id]);
    const name = await db.query("SELECT fname, lname FROM teacher WHERE employee_id = $1", [user.employee_id]);
    req.session.username = name.rows[0].fname + " " + name.rows[0].lname;
    res.render("teacher/classes.ejs", {classes: result.rows, username: req.session.username, currentAnnoun : true});   
  } catch (err) {
    console.log("Error loading teacher page: ", err);
  }
} else {
  res.redirect("/login/teacher");
}
});

app.get("/teacher/announcements/class" , async(req, res) => {
  if(req.isAuthenticated()){
    try {
      const classname = req.session.classname;
      // req.session.classname = null;
      const result = await db.query("SELECT * FROM class WHERE name = $1",[classname]);
      // console.log(result.rows[0]);
      res.render("teacher/class_announ.ejs", {announcements: result.rows[0].announcements, classname: classname, currentAnnoun: true, username: req.session.username});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});

app.get("/teacher/announcement", async(req, res) => {
  if (req.isAuthenticated()) {
    try {
      const annInd = req.session.annInd;
      const classname = req.session.classname;
      const result = await db.query("SELECT announcements FROM class WHERE name = $1",[classname]);
      res.render("teacher/announcement_page.ejs", {announcement: result.rows[0].announcements[annInd], username: req.session.username, currentAnnoun: true});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});

app.get("/teacher/attendance", async(req, res)=> {
  if(req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT name FROM staff s JOIN class c ON c.id = s.class_id WHERE s.teacher_id = $1 ORDER BY c.id ASC", [req.user.employee_id]);
      res.render("teacher/classes.ejs", {classes :result.rows, username: req.session.username, currentAtten: true});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});

app.get("/teacher/attendance/class", async(req, res)=>{
  if(req.isAuthenticated()){
    try {
      const result = await db.query("SELECT admnno, fname, lname, attendance, total_days, class_id FROM enrollment e JOIN class c ON c.id = e.class_id JOIN student s ON s.admnno = e.student_admnno WHERE c.name = $1 ORDER BY s.id ASC ",[req.session.classname]);
      req.session.classid = result.rows[0].class_id;
      res.render("teacher/attendance.ejs", {students: result.rows,classname: req.session.classname, username: req.session.username, currentAtten: true});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});

app.get("/teacher/results", async(req, res)=> {
  if(req.isAuthenticated()){
    try {
      const result = await db.query("SELECT name FROM staff s JOIN class c ON c.id = s.class_id WHERE s.teacher_id = $1 ORDER BY c.id ASC", [req.user.employee_id]);
      res.render("teacher/classes.ejs", {classes: result.rows, username: req.session.username, currentRes: true});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});

app.get("/teacher/results/class", async(req, res)=> {
  if (req.isAuthenticated()) {
    try {
        var studentlist = null;
        var testname = null;
      if(req.session.testname){
        var result = await db.query(`SELECT admnno, fname, lname, ${req.session.testname} FROM enrollment e JOIN class c ON c.id = e.class_id JOIN student stu ON stu.admnno = e.student_admnno WHERE c.name = $1 ORDER BY stu.id ASC`,[req.session.classname]);
        studentlist = result.rows;
        testname = req.session.testname;
      }
      res.session.testname = null;
      res.render("teacher/results.ejs", {classname: req.session.classname, username: req.session.username, currentRes: true, students: studentlist, testname: testname});
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login/teacher");
  }
});



app.get("/logout/teacher", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login/teacher");
  });
});


// POST reqs

app.post(
  "/login/teacher",
  passport.authenticate("teacher-local", {
    successRedirect: "/teacher/announcements",
    failureRedirect: "/login/teacher",
  })
);

app.post("/teacher/announcements/class", (req, res)=>{
  req.session.classname = req.body.class;
  res.redirect("/teacher/announcements/class");
});

app.post("/teacher/announcement", (req,res)=>{
  req.session.annInd = parseInt(req.body.index);
  res.redirect("/teacher/announcement");
});

app.post("/announcements/class/new", async(req, res)=> {
  await db.query("UPDATE class SET announcements = announcements || ARRAY[ARRAY[$1,$2]] WHERE name = $3",[req.body.title, req.body.content, req.session.classname]);
  res.redirect("/teacher/announcements/class");
});

app.post("/teacher/attendance/class", (req, res)=> {
  req.session.classname = req.body.class;
  res.redirect("/teacher/attendance/class");
});

app.post("/class/attendance", async(req, res)=> {
  const present = req.body.present;
  present.forEach(async(admnno) => {
    await db.query("UPDATE enrollment SET attendance = attendance+1 WHERE student_admnno = $1 AND class_id = $2",[admnno, req.session.classid]);
  });
  await db.query("UPDATE class SET total_days = total_days+1 WHERE id = $1",[req.session.classid]);
  req.session.classid = null;
  res.redirect("/teacher/attendance/class")
});

app.post("/teacher/results/class", (req, res)=>{
  req.session.classname = req.body.class;
  res.redirect("/teacher/results/class");
});

app.post("/results/exam", (req, res)=> {
  req.session.testname = req.body.testname;
  res.redirect("/teacher/results/class");
});
//Register new teacher

app.post("/register/teacher", async (req, res) => {
  const employee_id = req.body.userid;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM faculty_users WHERE employee_id = $1", [
      employee_id,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login/teacher");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO faculty_users (employee_id, password) VALUES ($1, $2) RETURNING *",
            [employee_id, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/teacher/announcements");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


// Passport Authentication

passport.use(
  "teacher-local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM faculty_users WHERE employee_id = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);


//cookies

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});


app.listen(port, ()=> {
    console.log(`Server running on port: ${port}`);
});