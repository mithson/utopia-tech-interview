import express, { Express, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
const path = require('path');
const bodyParser = require('body-parser');
import mongoose, { Document, Schema, ConnectOptions } from 'mongoose';


const port = 8000;
const app = express();
app.use(bodyParser.json());

const accessTokenSecret = 'your access token secret';
const refreshTokenSecret = 'your refresh token secret';

app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as ConnectOptions)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model('User', userSchema);

app.get('/', (req: Request, res: Response) => {
  res.send("⚡️[server] up and running");
})


// Set up body-parser middleware
app.use(bodyParser.urlencoded({ extended: false }));

// Set up static files directory
app.use(express.static(path.join(__dirname, 'public')));

// Set up GET route for signup form
app.get('/signup', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'public/signup.html'));
});


// Set up GET route for login form
app.get('/login', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'public/login.html'));
});


// Set up a sample dashboard route
app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to the Node Js/ Express App !');
});


// Route handler for fetching all users
app.get('/users', async (req: Request, res: Response) => {
  try {
    // Fetch all users from the database
    const users = await User.find();
    console.log(`All Users are -- ${users}`)

    // Extract password and username from each user
    const extractedUsers = users.map(user => {
      return user;
    });

    res.json(extractedUsers);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users'});
  }
});

// Signup
app.post('/signup', async (req: Request, res: Response) => {
  // Fetch all users from the database
  const users = await User.find();

  const { username, password } = req.body;
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  // Create a new user and add it to the array
  const user = { username, password: bcrypt.hashSync(password, 10), accessToken: "accesstoken", refreshToken: "refreshToken" };
  const userData = User.create(user);
  console.log(users)
  res.status(201).json({ message: 'User created successfully' });
});

app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    // Find the user in the database by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Incorrect password' });
    }

    // Generate new access token
    const accessToken = generateAccessToken(user.username);
    const refreshToken = jwt.sign({ username: user.username }, refreshTokenSecret);

    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Error occurred during login'  });
  }
});


// Token Refresh
app.post('/token', (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.sendStatus(401);
  }

  jwt.verify(refreshToken, refreshTokenSecret, (err: any, user: any) => {
    if (err) {
      return res.sendStatus(403);
    }
    const accessToken = generateAccessToken(user.username);
    res.json({ accessToken });
  });
});

app.delete('/deleteUser', authenticateToken, async (req: Request, res: Response) => {
  const { username } = req.body;
  const authenticatedUser = (req as any).user.username;

  try {
    const userToDelete = await User.findOne({ username });

    if (!userToDelete) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the authenticated user is the owner of the account
    if (userToDelete.username !== authenticatedUser) {
      return res.status(403).json({ message: 'Access denied - Akhir karna kya chahte ho' });
    }

    const deletedUser = await User.findOneAndDelete({ username });

    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error occurred during user deletion' });
  }
});



// Middleware to authenticate the access token
function authenticateToken(req: Request, res:Response, next: () => void) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }
  jwt.verify(token, accessTokenSecret, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    (req as any).user = user;
    next();
  });
}

// Function to generate access token
function generateAccessToken(username: String) {
  return jwt.sign({ username }, accessTokenSecret, { expiresIn: '120s' });
}


app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});