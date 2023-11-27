import express from 'express';
const app = express()
import db from './queries.js'
import cors from 'cors'
import bodyParser from 'body-parser';
import multer from 'multer';

app.use(cors())

app.use(bodyParser.json())
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, './uploads/');
    },
    filename: function(req, file, cb) {
        let randomPostfix = (Math.floor(Math.random() * 1000000) + 1).toString();
        cb(null, randomPostfix + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

app.get('/', (request, response) => {
    response.json({ info: 'Node.js, Express, and Postgres API' })
})

app.post('/register', db.register);
app.post('/auth', db.auth);
app.post('/createRequest', db.createRequest);
app.get('/getRequestsByCreator', db.getRequestsByCreator);
app.get('/getRequestsByStatus', db.getRequestsByStatus);


let port = process.env.PORT || 3030;

app.listen(port, (err) => {
    if (err){
        throw Error(err);
    }
    console.log(`Backend running on port ${port}.`)
})