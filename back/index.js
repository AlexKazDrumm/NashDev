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
app.post('/createRequest', upload.array('files'), db.createRequest);
app.post('/getRequestsByCreator', db.getRequestsByCreator);
app.post('/getRequestsByStatus', db.getRequestsByStatus);
app.post('/getAllRequestCategories', db.getAllRequestCategories);
app.post('/hideUserTip', db.hideUserTip);
app.post('/deleteRequestFile', db.deleteRequestFile);
app.post('/updateRequest', db.updateRequest);
app.post('/cancelRequest', db.cancelRequest);
app.post('/getAllRequests', db.getAllRequests);
app.post('/submitApplication', db.submitApplication);
app.post('/getApplicationResponses', db.getApplicationResponses);
app.post('/respondToApplication', db.respondToApplication);
app.post('/getMyApplications', db.getMyApplications);
app.post('/getApplicationsByRequest', db.getApplicationsByRequest);
app.post('/assignManagerToRequest', db.assignManagerToRequest);
app.post('/cancelManagerAssignment', db.cancelManagerAssignment);
app.post('/attachTzToRequest', upload.single('documentFile'), db.attachTzToRequest);
app.post('/createTask', db.createTask);
app.post('/duplicateTask', db.duplicateTask);
app.post('/archiveTask', db.archiveTask);
app.post('/getManagerTasks', db.getManagerTasks);
app.post('/getManagerTasksByRequest', db.getManagerTasksByRequest);
app.post('/updateAvatar', db.updateAvatar);
app.post('/sendVerificationCode', db.sendVerificationCode);
app.post('/changeEmail', db.changeEmail);
app.post('/changePassword', db.changePassword);
app.post('/changeName', db.changeName);
app.post('/changePhone', db.changePhone);
app.post('/createUserRequisites', db.createUserRequisites);
app.post('/getCardDataByToken', db.getCardDataByToken);
app.post('/verifyCvv', db.verifyCvv);

let port = process.env.PORT || 3034;

app.listen(port, (err) => {
    if (err){
        throw Error(err);
    }
    console.log(`Backend running on port ${port}.`)
})