const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const _ = require('lodash');
const session = require('express-session');
const passport = require('passport');
const MongoStore = require('connect-mongo');
const user_collection = require("./models/userModel");
const society_collection = require("./models/societyModel");
const visit_collection = require("./models/visitModel");
const db = require(__dirname+'/config/db');
const date = require(__dirname+'/date/date');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');

// Access environment variables
dotenv.config();
require('dotenv').config();
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
db.connectDB();

// Routes
app.get("/", async (req, res) => {
  try {
    let pageVisit = await visit_collection.Visit.findOne();
    if (!pageVisit) {
      pageVisit = new visit_collection.Visit({
        count: 0
      });
    }
    if (process.env.NODE_ENV === 'production') {
      pageVisit.count += 1;
    }
    await pageVisit.save();
    
    const societies = await society_collection.Society.find();
    const cities = societies.map(society => society.societyAddress.city.toLowerCase());
    const cityCount = new Set(cities).size;
    
    const foundUser = await user_collection.User.find();
    
    res.render("index", {
      city: cityCount,
      society: societies.length,
      user: foundUser.length,
      visit: pageVisit.count
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/signup", (req, res) => {
  society_collection.Society.find()
    .then(societies => {
      res.render("signup", { societies });
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    if (req.user.validation == 'approved') {
      res.render("home");
    } else if (req.user.validation == 'applied') {
      res.render("homeStandby", {
        icon: 'fa-user-clock',
        title: 'Account pending for approval',
        content: 'Your account will be active as soon as it is approved by your community.' +
                 'It usually takes 1-2 days for approval. If it is taking longer to get approval, ' +
                 'contact your society admin.'
      });
    } else {
      res.render("homeStandby", {
        icon: 'fa-user-lock',
        title: 'Account approval declined',
        content: 'Your account registration has been declined. ' +
                 'Please contact the society administrator for more details.' +
                 'You can edit the request and apply again.'
      });
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/newRequest", (req, res) => {
  if (req.isAuthenticated() && req.user.validation != 'approved') {
    society_collection.Society.find()
      .then(societies => {
        res.render("signupEdit", { user: req.user, societies });
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/home");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function() {
    res.redirect("/");
  });
});

app.get("/loginFailure", (req, res) => {
  const failureMessage = "Sorry, entered password was incorrect, Please double-check.";
  const hrefLink = "/login";
  const secondaryMessage = "Account not created?";
  const hrefSecondaryLink = "/signup";
  const secondaryButton = "Create Account";
  res.render("failure", {
    message: failureMessage,
    href: hrefLink,
    messageSecondary: secondaryMessage,
    hrefSecondary: hrefSecondaryLink,
    buttonSecondary: secondaryButton
  });
});

app.get("/residents", async (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    try {
      const userSocietyName = req.user.societyName;
      
      const allSocietyUsers = await user_collection.User.find({
        societyName: userSocietyName,
      });

      const foundUsers = [];
      const foundAppliedUsers = [];

      allSocietyUsers.forEach((user) => {
        if (user.validation === "approved") {
          foundUsers.push(user);
        } else if (user.validation === "applied") {
          foundAppliedUsers.push(user);
        }
      });
      
      res.render("residents", {
        societyResidents: foundUsers,
        appliedResidents: foundAppliedUsers,
        societyName: userSocietyName,
        isAdmin: req.user.isAdmin
      });
    } catch (err) {
      console.error(err);
      res.status(500).send("Server error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/noticeboard", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    society_collection.Society.findOne(
      { societyName: req.user.societyName },
      { noticeboard: 1 }
    )
      .then((foundSociety) => {
        if (foundSociety) {
          if (
            !foundSociety.noticeboard ||
            !foundSociety.noticeboard.length
          ) {
            foundSociety.noticeboard = [
              {
                subject: "Access all important announcements, notices and circulars here.",
              },
            ];
          }
          res.render("noticeboard", {
            notices: foundSociety.noticeboard,
            isAdmin: req.user.isAdmin,
          });
        }
      })
      .catch((err) => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/notice", (req, res) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    res.render("notice");
  } else {
    res.redirect("/login");
  }
});

app.get("/bill", async (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    try {
      const foundUser = await user_collection.User.findById(req.user.id);
      const foundSociety = await society_collection.Society.findOne({ societyName: foundUser.societyName });
      
      const dateToday = new Date();
      let totalMonth = 0;
      let dateFrom = foundUser.createdAt;
      if (foundUser.lastPayment.date) {
        dateFrom = foundUser.lastPayment.date;
        totalMonth = date.monthDiff(dateFrom, dateToday);
      } else {
        totalMonth = date.monthDiff(dateFrom, dateToday) + 1;
      }
      
      const monthlyTotal = Object.values(foundSociety.maintenanceBill)
        .filter(ele => typeof(ele) == 'number')
        .reduce((sum, ele) => sum + ele, 0);
        
      let credit = 0;
      let due = 0;
      if (totalMonth == 0) {
        credit = monthlyTotal;
      } else if (totalMonth > 1) {
        due = (totalMonth - 1) * monthlyTotal;
      }
      const totalAmount = monthlyTotal + due - credit;
      
      const foundUsers = await user_collection.User.find({
        $and: [
          { "societyName": req.user.societyName },
          { "validation": "approved" }
        ]
      });
      
      foundUser.makePayment = totalAmount;
      await foundUser.save();
      
      res.render("bill", {
        resident: foundUser,
        society: foundSociety,
        totalAmount: totalAmount,
        pendingDue: due,
        creditBalance: credit,
        monthName: date.month,
        date: date.today,
        year: date.year,
        receipt: foundUser.lastPayment,
        societyResidents: foundUsers,
        monthlyTotal: monthlyTotal
      });
    } catch (err) {
      console.error(err);
      res.status(500).send("Server error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/editBill", (req, res) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    society_collection.Society.findOne(
      { societyName: req.user.societyName },
      { maintenanceBill: 1 }
    )
      .then(foundSociety => {
        if (foundSociety) {
          res.render("editBill", { maintenanceBill: foundSociety.maintenanceBill });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/payBill", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const foundUser = await user_collection.User.findById(req.user.id);
      if (!foundUser) {
        return res.status(404).send("User not found");
      }
      const foundSociety = await society_collection.Society.findOne({ societyName: foundUser.societyName });
      if (!foundSociety) {
        return res.status(404).send("Society not found");
      }

      const dateToday = new Date();
      let totalMonth = 0;
      let dateFrom = foundUser.createdAt;
      if (foundUser.lastPayment.date) {
        dateFrom = foundUser.lastPayment.date;
        totalMonth = date.monthDiff(dateFrom, dateToday);
      } else {
        totalMonth = date.monthDiff(dateFrom, dateToday) + 1;
      }
      const monthlyTotal = Object.values(foundSociety.maintenanceBill)
        .filter(ele => typeof(ele) == 'number')
        .reduce((sum, ele) => sum + ele, 0);
      let credit = totalMonth === 0 ? monthlyTotal : 0;
      let due = totalMonth > 1 ? (totalMonth - 1) * monthlyTotal : 0;
      const totalAmount = monthlyTotal + due - credit;

      res.render("payBill", {
        resident: foundUser,
        society: foundSociety,
        monthName: date.month,
        year: date.year,
        creditBalance: credit,
        pendingDue: due,
        totalAmount: totalAmount,
        razorpayKeyId: process.env.RAZORPAY_KEY_ID,
      });
    } catch (err) {
      console.error("PayBill error:", err);
      res.status(500).send("Server error");
    }
  } else {
    res.redirect("/login");
  }
});

app.post('/create-order', async (req, res) => {
  try {
    const { amount, currency, receipt } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const options = {
      amount: amount * 100,
      currency: currency || 'INR',
      receipt: receipt || `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
    });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({ error: error.message || 'Failed to create order' });
  }
});

app.post('/verify-payment', (req, res) => {
  const crypto = require('crypto');
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const generatedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (generatedSignature === razorpay_signature) {
    res.json({ status: 'success' });
  } else {
    res.status(400).json({ error: 'Invalid signature' });
  }
});

app.get('/payment-success', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const { payment_id, order_id } = req.query;

  try {
    const payment = await razorpay.payments.fetch(payment_id);
    if (payment.status !== 'captured') {
      return res.status(400).send('Payment not captured');
    }

    const foundUser = await user_collection.User.findById(req.user.id);
    foundUser.lastPayment = {
      date: new Date(),
      amount: payment.amount / 100,
      paymentId: payment_id,
      orderId: order_id,
    };
    foundUser.makePayment = 0;
    await foundUser.save();

    const foundSociety = await society_collection.Society.findOne({ societyName: foundUser.societyName });

    res.render('paymentSuccess', {
      paymentId: payment_id,
      orderId: order_id,
      amount: payment.amount / 100,
      date: new Date().toLocaleDateString(),
      resident: foundUser,
      society: foundSociety,
    });
  } catch (error) {
    console.error('Error in payment-success route:', error);
    res.status(500).send('Error retrieving payment details');
  }
});

app.get("/admincomplaint", (req, res) => {
  console.log("Accessing /admincomplaint route");
  if (req.isAuthenticated()) {
    console.log("User authenticated:", req.user);
    if (req.user.isAdmin && req.user.validation === 'approved') {
      console.log("Rendering admincomplaint.ejs");
      res.render("admincomplaint");
    } else {
      console.log("User not admin or not approved, redirecting to /login");
      res.redirect("/login");
    }
  } else {
    console.log("User not authenticated, redirecting to /login");
    res.redirect("/login");
  }
});

app.post("/admincomplaint", async (req, res) => {
  console.log("POST /admincomplaint route accessed");
  try {
    const foundUser = await user_collection.User.findById(req.user.id);
    if (foundUser && req.user.isAdmin && req.user.validation === 'approved') {
      console.log("Saving admin complaint for user:", foundUser._id);
      const complaint = {
        date: date.dateString,
        category: req.body.category,
        type: req.body.type,
        description: req.body.description,
        status: 'open',
        escalated: true
      };
      foundUser.complaints.push(complaint);
      await foundUser.save();

      console.log("Sending email to higher authority");
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.HIGHER_AUTHORITY_EMAIL,
        subject: `New Admin Complaint: ${req.body.category}`,
        text: `A new complaint has been raised by ${foundUser.firstName} ${foundUser.lastName} (${foundUser.flatNumber}) from ${foundUser.societyName}.\n\n` +
              `Category: ${req.body.category}\n` +
              `Type: ${req.body.type}\n` +
              `Description: ${req.body.description}\n` +
              `Date: ${date.dateString}\n\n` +
              `Please review and take appropriate action.`
      };

      await transporter.sendMail(mailOptions);
      console.log("Email sent, redirecting to /helpdesk");
      res.redirect("/helpdesk");
    } else {
      console.log("Unauthorized access, redirecting to /login");
      res.redirect("/login");
    }
  } catch (err) {
    console.error("Error in /admincomplaint POST:", err);
    res.status(500).send("Server error");
  }
});

app.get("/helpdesk", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    if (req.user.isAdmin) {
      user_collection.User.find({
        $and: [
          { "societyName": req.user.societyName }, 
          { "validation": "approved" }
        ]
      })
        .then(foundUsers => {
          res.render("helpdeskAdmin", { users: foundUsers });
        })
        .catch(err => {
          console.error(err);
          res.status(500).send("Server error");
        });
    } else {
      if (!req.user.complaints.length) {
        req.user.complaints = [{
          'category': 'You have not raised any complaint',
          'description': 'You can raise complaints and track their resolution by facility manager.'
        }];
      }
      res.render("helpdesk", { complaints: req.user.complaints });
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/complaint", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    res.render("complaint");
  } else {
    res.redirect("/login");
  }
});

app.get("/contacts", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    const userSocietyName = req.user.societyName;
    society_collection.Society.findOne(
      { "societyName": userSocietyName },
      { emergencyContacts: 1 }
    )
      .then(foundSociety => {
        if (foundSociety) {
          res.render("contacts", { contact: foundSociety.emergencyContacts, isAdmin: req.user.isAdmin });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/editContacts", (req, res) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    society_collection.Society.findOne(
      { societyName: req.user.societyName },
      { emergencyContacts: 1 }
    )
      .then(foundSociety => {
        if (foundSociety) {
          res.render("editContacts", { contact: foundSociety.emergencyContacts });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/profile", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    user_collection.User.findById(req.user.id)
      .then(foundUser => {
        if (foundUser) {
          return society_collection.Society.findOne({ societyName: foundUser.societyName })
            .then(foundSociety => {
              res.render("profile", { resident: foundUser, society: foundSociety });
            });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/editProfile", (req, res) => {
  if (req.isAuthenticated() && req.user.validation == 'approved') {
    user_collection.User.findById(req.user.id)
      .then(foundUser => {
        if (foundUser) {
          return society_collection.Society.findOne({ societyName: foundUser.societyName })
            .then(foundSociety => {
              res.render("editProfile", { resident: foundUser, society: foundSociety });
            });
        }
      })
      .catch(err => {
        console.error(err);
        res.status(500).send("Server error");
      });
  } else {
    res.redirect("/login");
  }
});

app.get('/success', async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
    const customer = await stripe.customers.retrieve(session.customer);
    
    const foundUser = await user_collection.User.findOne({ _id: req.user.id });
    foundUser.lastPayment.date = new Date(customer.created * 1000);
    foundUser.lastPayment.amount = session.amount_total / 100;
    foundUser.lastPayment.invoice = customer.invoice_prefix;
    
    await foundUser.save();
    
    const transactionDate = new Date(customer.created * 1000).toLocaleString().split(', ')[0];
    res.render("success", {
      invoice: customer.invoice_prefix,
      amount: session.amount_total / 100,
      date: transactionDate
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.post('/checkout-session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [
      {
        price_data: {
          currency: 'inr',
          product_data: {
            name: req.user.societyName,
            images: ['https://www.flaticon.com/svg/vstatic/svg/3800/3800/3800518.svg?token=exp=1615226542~hmac=7b5bcc7eceab928716515ebf044f16cd'],
          },
          unit_amount: req.user.makePayment * 100,
        },
        quantity: 1,
      },
    ],
    mode: 'payment',
    success_url: "https://esociety-fdbd.onrender.com/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: "https://esociety-fdbd.onrender.com/bill",
  });
  
  res.json({ id: session.id });
});

app.post("/approveResident", (req, res) => {
  const user_id = Object.keys(req.body.validate)[0];
  const validate_state = Object.values(req.body.validate)[0];
  user_collection.User.updateOne(
    { _id: user_id },
    { $set: { validation: validate_state } }
  ).then(() => res.redirect("/residents"));
});

app.post("/complaint", (req, res) => {
  user_collection.User.findById(req.user.id)
    .then(foundUser => {
      if (foundUser) {
        const complaint = {
          date: date.dateString,
          category: req.body.category,
          type: req.body.type,
          description: req.body.description,
          status: 'open'
        };
        foundUser.complaints.push(complaint);
        return foundUser.save()
          .then(() => {
            res.redirect("/helpdesk");
          });
      }
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/closeTicket", (req, res) => {
  const user_id = Object.keys(req.body.ticket)[0];
  const ticket_index = Object.values(req.body.ticket)[0];
  const ticket = 'complaints.' + ticket_index;
  
  user_collection.User.findById(user_id)
    .then(foundUser => {
      if (foundUser) {
        return user_collection.User.updateOne(
          { _id: user_id },
          {
            $set: {
              [ticket]: {
                status: 'close',
                date: foundUser.complaints[ticket_index].date,
                category: foundUser.complaints[ticket_index].category,
                type: foundUser.complaints[ticket_index].type,
                description: foundUser.complaints[ticket_index].description
              }
            }
          }
        )
          .then(() => {
            res.redirect("/helpdesk");
          });
      }
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/notice", (req, res) => {
  society_collection.Society.findOne({ societyName: req.user.societyName })
    .then(foundSociety => {
      if (foundSociety) {
        const notice = {
          date: date.dateString,
          subject: req.body.subject,
          details: req.body.details
        };
        foundSociety.noticeboard.push(notice);
        return foundSociety.save()
          .then(() => {
            res.redirect("/noticeboard");
          });
      }
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/editBill", (req, res) => {
  society_collection.Society.updateOne(
    { societyName: req.user.societyName },
    {
      $set: {
        maintenanceBill: {
          societyCharges: req.body.societyCharges,
          repairsAndMaintenance: req.body.repairsAndMaintenance,
          sinkingFund: req.body.sinkingFund,
          waterCharges: req.body.waterCharges,
          insuranceCharges: req.body.insuranceCharges,
          parkingCharges: req.body.parkingCharges
        }
      }
    }
  )
    .then(() => {
      res.redirect("/bill");
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/editContacts", (req, res) => {
  society_collection.Society.updateOne(
    { societyName: req.user.societyName },
    {
      $set: {
        emergencyContacts: {
          plumbingService: req.body.plumbingService,
          medicineShop: req.body.medicineShop,
          ambulance: req.body.ambulance,
          doctor: req.body.doctor,
          fireStation: req.body.fireStation,
          guard: req.body.guard,
          policeStation: req.body.policeStation
        }
      }
    }
  )
    .then(() => {
      res.redirect("/contacts");
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/editProfile", (req, res) => {
  user_collection.User.updateOne(
    { _id: req.user.id },
    {
      $set: {
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        phoneNumber: req.body.phoneNumber,
        flatNumber: req.body.flatNumber
      }
    }
  )
    .then(() => {
      if (req.body.address) {
        return society_collection.Society.updateOne(
          { admin: req.user.username },
          {
            $set: {
              societyAddress: {
                address: req.body.address,
                city: req.body.city,
                district: req.body.district,
                postalCode: req.body.postalCode
              }
            }
          }
        )
          .then(() => {
            res.redirect("/profile");
          });
      } else {
        res.redirect("/profile");
      }
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/newRequest", (req, res) => {
  society_collection.Society.findOne({ societyName: req.body.societyName })
    .then(foundSociety => {
      if (foundSociety) {
        return user_collection.User.updateOne(
          { _id: req.user.id },
          {
            $set: {
              firstName: req.body.firstName,
              lastName: req.body.lastName,
              phoneNumber: req.body.phoneNumber,
              societyName: req.body.societyName,
              flatNumber: req.body.flatNumber,
              validation: 'applied'
            }
          }
        )
          .then(() => {
            res.redirect("/home");
          });
      } else {
        const failureMessage = "Sorry, society is not registered, Please double-check society name.";
        const hrefLink = "/newRequest";
        const secondaryMessage = "Account not created?";
        const hrefSecondaryLink = "/signup";
        const secondaryButton = "Create Account";
        res.render("failure", {
          message: failureMessage,
          href: hrefLink,
          messageSecondary: secondaryMessage,
          hrefSecondary: hrefSecondaryLink,
          buttonSecondary: secondaryButton
        });
      }
    })
    .catch(err => {
      console.error(err);
      res.status(500).send("Server error");
    });
});

app.post("/signup", async (req, res) => {
  try {
    const foundSociety = await society_collection.Society.findOne({ societyName: req.body.societyName });
    
    if (foundSociety) {
      const user = await user_collection.User.register(
        {
          username: req.body.username,
          societyName: req.body.societyName,
          flatNumber: req.body.flatNumber,
          firstName: req.body.firstName,
          lastName: req.body.lastName,
          phoneNumber: req.body.phoneNumber
        },
        req.body.password
      );

      await new Promise((resolve, reject) => {
        req.login(user, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      
      res.redirect("/home");
    } else {
      const failureMessage = "Sorry, society is not registered, Please double-check society name.";
      const hrefLink = "/signup";
      const secondaryMessage = "Society not registered?";
      const hrefSecondaryLink = "/register";
      const secondaryButton = "Register Society";
      res.render("failure", {
        message: failureMessage,
        href: hrefLink,
        messageSecondary: secondaryMessage,
        hrefSecondary: hrefSecondaryLink,
        buttonSecondary: secondaryButton
      });
    }
  } catch (err) {
    console.error(err);
    const failureMessage = "Sorry, this email address is not available. Please choose a different address.";
    const hrefLink = "/signup";
    const secondaryMessage = "Society not registered?";
    const hrefSecondaryLink = "/register";
    const secondaryButton = "Register Society";
    res.render("failure", {
      message: failureMessage,
      href: hrefLink,
      messageSecondary: secondaryMessage,
      hrefSecondary: hrefSecondaryLink,
      buttonSecondary: secondaryButton
    });
  }
});

app.post("/register", async (req, res) => {
  try {
    const existingSociety = await society_collection.Society.findOne({ societyName: req.body.societyName });
    
    if (!existingSociety) {
      const user = await user_collection.User.register(
        {
          validation: 'approved',
          isAdmin: true,
          username: req.body.username,
          societyName: req.body.societyName,
          flatNumber: req.body.flatNumber,
          firstName: req.body.firstName,
          lastName: req.body.lastName,
          phoneNumber: req.body.phoneNumber
        },
        req.body.password
      );
      
      await new Promise((resolve, reject) => {
        req.login(user, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      
      const society = new society_collection.Society({
        societyName: user.societyName,
        societyAddress: {
          address: req.body.address,
          city: req.body.city,
          district: req.body.district,
          postalCode: req.body.postalCode
        },
        admin: user.username
      });
      
      await society.save();
      res.redirect("/home");
    } else {
      const failureMessage = "Sorry, society is already registered, Please double-check society name.";
      const hrefLink = "/register";
      const secondaryMessage = "Account not created?";
      const hrefSecondaryLink = "/signup";
      const secondaryButton = "Create Account";
      res.render("failure", {
        message: failureMessage,
        href: hrefLink,
        messageSecondary: secondaryMessage,
        hrefSecondary: hrefSecondaryLink,
        buttonSecondary: secondaryButton
      });
    }
  } catch (err) {
    console.error(err);
    res.redirect("/register");
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/home",
  failureRedirect: "/loginFailure"
}));

app.get("/health", (req, res) => {
  res.status(200).send("Server is running");
});

app.listen(
  process.env.PORT || 3000,
  '0.0.0.0',
  () => console.log('Server started on 0.0.0.0:' + (process.env.PORT || 3000))
);