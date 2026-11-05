// ============================================================
// 𝐑𝟑𝐃𝐈𝐑𝟑𝐂𝐓 - server.js (fixed)
// ============================================================

const express = require('express');
const dotenv = require('dotenv');
const uaParser = require('ua-parser-js');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const fsp = require('fs').promises;
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const cors = require('cors');
const Joi = require('joi');
const bcrypt = require('bcrypt');

dotenv.config();

const app = express();

app.set('trust proxy', 1);

// Custom request ID middleware (no vulnerable uuid dependency)
app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});


// ============================================================
// Errors
// ============================================================

class AppError extends Error {
    constructor(message, statusCode = 500, code = 'ERROR') {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = true;
    }
}

class ValidationError extends AppError {
    constructor(message, details = []) {
        super(message, 400, 'VALIDATION_ERROR');
        this.details = details;
    }
}


// ============================================================
// Validation
// ============================================================

const trackerSchema = Joi.object({
    tracker_id: Joi.string()
        .alphanum()
        .max(32)
        .optional(),

    name: Joi.string()
        .min(1)
        .max(100)
        .required(),

    destination_url: Joi.string()
        .uri({
            scheme: ['https']
        })
        .required()
}).options({
    allowUnknown: false,
    stripUnknown: true
});


// ============================================================
// Helpers
// ============================================================

function successResponse(res, data, message = 'Success') {
    return res.json({
        success: true,
        message,
        data,
        timestamp: new Date().toISOString()
    });
}


function errorResponse(res, error) {

    console.error(error);

    if (error instanceof AppError) {
        return res.status(error.statusCode).json({
            success: false,
            error: error.message,
            code: error.code,
            details: error.details || null
        });
    }


    return res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
}



function escapeHtml(value) {

    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

}



function getClientIp(req) {

    const forwarded =
        req.headers['x-forwarded-for'];

    const ip =
        forwarded ||
        req.socket.remoteAddress ||
        'Unknown';


    return String(ip)
        .split(',')[0]
        .replace('::ffff:', '')
        .trim();

}



function generateTrackerId() {

    return crypto
        .randomBytes(4)
        .toString('hex');

}



// ============================================================
// Database
// ============================================================

let pool = null;
let useDb = false;


function getDbSslConfig() {

    if (
        process.env.DATABASE_URL &&
        process.env.DATABASE_URL.includes('render.com')
    ) {
        return {
            rejectUnauthorized: false
        };
    }


    return {
        rejectUnauthorized: false
    };

}



async function initDatabase() {

    if (!process.env.DATABASE_URL) {

        console.log(
            'No DATABASE_URL found, using file storage'
        );

        return;
    }


    try {

        pool = new Pool({

            connectionString:
                process.env.DATABASE_URL,

            ssl:
                getDbSslConfig(),

            max: 20

        });


        await pool.query('SELECT 1');


        // FIX: volledige tracker tabel inclusief updated_at
        await pool.query(`
            CREATE TABLE IF NOT EXISTS trackers (
                tracker_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                destination_url TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now()
            );
        `);



        // FIX: bestaande databases krijgen ontbrekende kolom
        await pool.query(`
            ALTER TABLE trackers
            ADD COLUMN IF NOT EXISTS updated_at
            TIMESTAMPTZ DEFAULT now();
        `);



        await pool.query(`
            UPDATE trackers
            SET updated_at =
                COALESCE(updated_at, created_at, now())
            WHERE updated_at IS NULL;
        `);



        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                tracker_id TEXT NOT NULL,
                tracker_name TEXT,
                timestamp TIMESTAMPTZ DEFAULT now(),
                ip TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                browser TEXT,
                os TEXT,
                device TEXT,
                useragent TEXT,
                referer TEXT,
                latitude NUMERIC,
                longitude NUMERIC,
                is_pixel BOOLEAN DEFAULT false
            );
        `);



        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            idx_logs_tracker_id
            ON logs(tracker_id);
        `);



        useDb = true;

        console.log(
            'Postgres database connected'
        );


    } catch (err) {

        console.error(
            'Database init failed:',
            err
        );

        pool = null;
        useDb = false;
    }

}

// ============================================================
// Middleware
// ============================================================

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(compression());


app.use(cors({
    origin: process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(',')
        : true,
    credentials: true
}));


app.use(express.json({
    limit: '16kb'
}));

app.use(express.urlencoded({
    extended: true,
    limit: '16kb'
}));


app.use(express.static(
    path.join(__dirname, 'public'),
    {
        maxAge: '1d',
        etag: true
    }
));


// ============================================================
// Sessions
// ============================================================

let sessionStore = undefined;


if (process.env.DATABASE_URL) {

    sessionStore = new pgSession({

        conObject: {

            connectionString:
                process.env.DATABASE_URL,

            ssl:
                getDbSslConfig()

        },

        tableName: 'session',

        createTableIfMissing: true

    });

}



app.use(session({

    store: sessionStore,

    secret:
        process.env.SESSION_SECRET ||
        crypto.randomBytes(32)
            .toString('hex'),

    resave: false,

    saveUninitialized: false,

    name: 'sid',

    cookie: {

        httpOnly: true,

        secure:
            process.env.NODE_ENV === 'production',

        sameSite:
            process.env.NODE_ENV === 'production'
                ? 'strict'
                : 'lax',

        maxAge:
            24 * 60 * 60 * 1000

    }

}));



// ============================================================
// Auth
// ============================================================

const ADMIN_USER =
    process.env.ADMIN_USER || 'admin';

const ADMIN_PASS =
    process.env.ADMIN_PASS || 'change_me';

const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH;

async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  if (!hash && ADMIN_PASS === password) {
    console.warn('⚠️  WARNING: Using plain text password. Set ADMIN_PASS_HASH in .env for security.');
    return true;
  }
  if (!hash) return false;
  return await bcrypt.compare(password, hash);
}



function requireAuth(req, res, next) {

    if (
        req.session &&
        req.session.authenticated
    ) {
        return next();
    }


    if (
        req.path.startsWith('/api/')
    ) {

        return res.status(401)
            .json({
                error:
                'Niet ingelogd'
            });

    }


    res.redirect('/login');

}



// ============================================================
// Rate limits
// ============================================================

const authLimiter = rateLimit({

    windowMs:
        15 * 60 * 1000,

    max: 5,

    message: {
        error:
        'Te veel login pogingen'
    }

});



const geoLimiter = rateLimit({

    windowMs:
        60 * 1000,

    max: 10

});



const pixelLimiter = rateLimit({

    windowMs:
        60 * 1000,

    max: 20

});




// ============================================================
// Storage
// ============================================================

const TRACKERS_FILE =
    path.join(
        __dirname,
        'trackers.json'
    );


const LOG_FILE =
    path.join(
        __dirname,
        'logs.txt'
    );


const DEFAULT_REDIRECT_URL =
    process.env.DEFAULT_REDIRECT_URL ||
    'https://youtube.com';



async function readTrackersFile() {

    try {

        const data =
            await fsp.readFile(
                TRACKERS_FILE,
                'utf8'
            );


        return JSON.parse(data);


    } catch {

        return [];

    }

}



async function writeTrackersFile(trackers) {

    await fsp.writeFile(

        TRACKERS_FILE,

        JSON.stringify(
            trackers,
            null,
            2
        )

    );

}



// ============================================================
// Tracker database functions
// ============================================================


async function loadTrackers() {

    if (useDb) {

        const result =
            await pool.query(`

                SELECT
                    tracker_id,
                    name,
                    destination_url,
                    created_at,
                    updated_at

                FROM trackers

                ORDER BY created_at DESC

            `);


        return result.rows;

    }


    return readTrackersFile();

}



async function loadTrackerById(id) {


    if (useDb) {

        const result =
            await pool.query(
                `
                SELECT *
                FROM trackers
                WHERE tracker_id=$1
                `,
                [id]
            );


        return result.rows[0];

    }



    const trackers =
        await readTrackersFile();


    return trackers.find(
        t => t.tracker_id === id
    );

}




async function saveTracker(data) {


    if (useDb) {


        await pool.query(`

            INSERT INTO trackers

            (
                tracker_id,
                name,
                destination_url,
                created_at,
                updated_at
            )

            VALUES
            (
                $1,
                $2,
                $3,
                now(),
                now()
            )


            ON CONFLICT(tracker_id)

            DO UPDATE SET

                name = EXCLUDED.name,

                destination_url =
                    EXCLUDED.destination_url,

                updated_at =
                    now()

        `,
        [
            data.tracker_id,
            data.name,
            data.destination_url
        ]);


        return;

    }



    const trackers =
        await readTrackersFile();


    const index =
        trackers.findIndex(
            t =>
            t.tracker_id === data.tracker_id
        );



    const now =
        new Date()
            .toISOString();



    if(index >= 0) {


        trackers[index] = {

            ...trackers[index],

            ...data,

            updated_at:
                now

        };


    } else {


        trackers.push({

            ...data,

            created_at:
                now,

            updated_at:
                now

        });

    }



    await writeTrackersFile(trackers);

}




async function deleteTrackerById(id) {


    if(useDb) {


        await pool.query(
            `
            DELETE FROM logs
            WHERE tracker_id=$1
            `,
            [id]
        );


        await pool.query(
            `
            DELETE FROM trackers
            WHERE tracker_id=$1
            `,
            [id]
        );


        return;

    }



    const trackers =
        await readTrackersFile();



    await writeTrackersFile(

        trackers.filter(
            t =>
            t.tracker_id !== id
        )

    );

}

// ============================================================
// Logging
// ============================================================

async function appendLog(log) {

    if (useDb) {

        await pool.query(`

            INSERT INTO logs

            (
                tracker_id,
                tracker_name,
                timestamp,
                ip,
                country,
                city,
                isp,
                browser,
                os,
                device,
                useragent,
                referer,
                latitude,
                longitude,
                is_pixel
            )

            VALUES
            (
                $1,$2,$3,$4,$5,$6,$7,
                $8,$9,$10,$11,$12,$13,$14,$15
            )

        `,
        [

            log.tracker_id,
            log.tracker_name,
            log.timestamp,
            log.ip,
            log.country,
            log.city,
            log.isp,
            log.browser,
            log.os,
            log.device,
            log.useragent,
            log.referer,
            log.latitude,
            log.longitude,
            log.is_pixel || false

        ]);


        return;

    }



    await fsp.appendFile(

        LOG_FILE,

        JSON.stringify(log) + '\n'

    );

}




async function getLogs(limit = 500) {


    if(useDb) {


        const result =
            await pool.query(`

                SELECT *

                FROM logs

                ORDER BY timestamp DESC

                LIMIT $1

            `,
            [limit]);


        return result.rows;

    }



    try {

        const data =
            await fsp.readFile(
                LOG_FILE,
                'utf8'
            );


        return data
            .split('\n')
            .filter(Boolean)
            .map(x => JSON.parse(x))
            .reverse()
            .slice(0, limit);


    } catch {

        return [];

    }

}



// ============================================================
// Routes
// ============================================================


// Home

app.get('/', (req,res)=>{

    res.sendFile(
        path.join(
            __dirname,
            'views',
            'index.html'
        )
    );

});




// Login page

app.get('/login',(req,res)=>{

    res.sendFile(
        path.join(
            __dirname,
            'views',
            'login.html'
        )
    );

});




// Login

app.post(
'/api/login',
authLimiter,
async(req,res)=>{

    const { error, value } = Joi.object({
        username: Joi.string().min(1).max(100).required(),
        password: Joi.string().min(1).max(200).required()
    }).options({ allowUnknown: false, stripUnknown: true }).validate(req.body);

    if (error) {
        return res.status(400).json({ error: 'Invalid credentials format' });
    }

    const {
        username,
        password
    } = value;



    if(
        username === ADMIN_USER &&
        await verifyPassword(password, ADMIN_PASS_HASH)
    ){

        req.session.authenticated = true;

        req.session.user = username;


        return res.json({
            success:true
        });

    }



    return res.status(401).json({

        error:
        'Ongeldige login'

    });


});




// Logout

app.post('/api/logout',(req,res)=>{

    req.session.destroy(()=>{

        res.json({
            success:true
        });

    });

});




// Admin

app.get(
'/admin',
requireAuth,
(req,res)=>{

    res.sendFile(
        path.join(
            __dirname,
            'views',
            'admin.html'
        )
    );

});




// Create tracker

app.post(
'/api/save-tracker',
requireAuth,
async(req,res)=>{


try {


    const {
        error,
        value
    } =
    trackerSchema.validate(
        req.body
    );



    if(error){

        throw new ValidationError(
            'Invalid input'
        );

    }



    let {
        tracker_id,
        name,
        destination_url

    } = value;



    if(!tracker_id){

        tracker_id =
            generateTrackerId();

    }



    await saveTracker({

        tracker_id,

        name,

        destination_url

    });



    return successResponse(

        res,

        {

            tracker_id,

            link:
            `/track/${tracker_id}`

        }

    );



}catch(err){

    errorResponse(
        res,
        err
    );

}


});




// List trackers

app.get(
'/api/trackers',
requireAuth,
async(req,res)=>{


    try {

        res.json(
            await loadTrackers()
        );


    }catch(err){

        errorResponse(
            res,
            err
        );

    }

});




// Delete tracker

app.post(
'/api/delete-tracker',
requireAuth,
async(req,res)=>{


    try {


        await deleteTrackerById(
            req.body.tracker_id
        );


        res.json({
            success:true
        });


    }catch(err){

        errorResponse(
            res,
            err
        );

    }

});




// Logs

app.get(
'/api/logs',
requireAuth,
async(req,res)=>{


    res.json(
        await getLogs()
    );


});




// Summary

app.get(
'/api/summary',
requireAuth,
async(req,res)=>{


    const trackers =
        await loadTrackers();


    const logs =
        await getLogs(500);



    res.json({

        totalTrackers:
            trackers.length,

        totalVisits:
            logs.length,

        uniqueVisits:
            new Set(
                logs.map(
                    x=>x.ip
                )
            ).size

    });


});




// Health MUST be before wildcard

app.get(
'/health',
(req,res)=>{


    res.json({

        status:'ok',

        database:
            useDb
            ? 'connected'
            : 'fallback',

        time:
            new Date()

    });


});




// Tracker redirect

async function redirectTracker(id,res){


    let url =
        DEFAULT_REDIRECT_URL;



    try {


        const tracker =
            await loadTrackerById(id);



        if(tracker?.destination_url){

            url =
            tracker.destination_url;

        }


    }catch(e){

        console.error(e);

    }



    res.redirect(url);

}




app.get(
'/track/:id',
async(req,res)=>{

    redirectTracker(
        req.params.id,
        res
    );

});




// FIX: wildcard helemaal onderaan

app.get(
'/:trackerId',
async(req,res,next)=>{


    const id =
        req.params.trackerId;



    if(
        [
            'api',
            'admin',
            'login',
            'health'
        ]
        .includes(
            id.toLowerCase()
        )
    ){

        return next();

    }



    redirectTracker(
        id,
        res
    );


});




// 404

app.use((req,res)=>{

    res.status(404).json({

        error:
        'Not found'

    });

});




// ============================================================
// Startup
// ============================================================

const PORT =
    process.env.PORT || 3000;



initDatabase()
.then(()=>{


    app.listen(
        PORT,
        ()=>{

            console.log(
                `R3DIRECT running on ${PORT}`
            );

        }
    );


})
.catch(err=>{


    console.error(
        'Startup failed',
        err
    );


});