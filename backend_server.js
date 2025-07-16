const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Minuten
    max: 100, // Limit auf 100 Requests pro IP
    message: 'Zu viele Anfragen von dieser IP'
});
app.use('/api/', limiter);

// Uploads-Ordner erstellen
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer für Datei-Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB Limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Nur Bilder sind erlaubt'));
        }
    }
});

// Datenbank initialisieren
const db = new sqlite3.Database('./cannabis_diary.db');

// Datenbank-Schema erstellen
db.serialize(() => {
    // Benutzer-Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Pflanzen-Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS plants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        strain TEXT,
        planted_date DATE NOT NULL,
        status TEXT CHECK(status IN ('vegetative', 'flowering', 'harvest')) DEFAULT 'vegetative',
        substrate TEXT,
        location TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    // Einträge-Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plant_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        date DATE NOT NULL,
        watering TEXT CHECK(watering IN ('none', 'water', 'nutrients')) DEFAULT 'none',
        water_amount INTEGER,
        nutrients TEXT,
        ph_value REAL,
        height INTEGER,
        repotted BOOLEAN DEFAULT 0,
        issues TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (plant_id) REFERENCES plants (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    // Bilder-Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_name TEXT,
        file_size INTEGER,
        mime_type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (entry_id) REFERENCES entries (id) ON DELETE CASCADE
    )`);

    // Standard-Benutzer erstellen (nur für Demo)
    const defaultPassword = bcrypt.hashSync('demo123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, email, password_hash) VALUES ('demo', 'demo@example.com', ?)`, [defaultPassword]);
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Zugriff verweigert' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token ungültig' });
        }
        req.user = user;
        next();
    });
};

// Auth Routes
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Datenbankfehler' });
        }

        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    });
});

app.post('/api/auth/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    db.run('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
        [username, email, passwordHash], function(err) {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(409).json({ error: 'Benutzername oder E-Mail bereits vergeben' });
            }
            return res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
        }

        const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ token, user: { id: this.lastID, username, email } });
    });
});

// Plants Routes
app.get('/api/plants', authenticateToken, (req, res) => {
    db.all('SELECT * FROM plants WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, plants) => {
        if (err) {
            return res.status(500).json({ error: 'Datenbankfehler' });
        }
        res.json(plants);
    });
});

app.post('/api/plants', authenticateToken, (req, res) => {
    const { name, strain, planted_date, status, substrate, location, notes } = req.body;

    if (!name || !planted_date) {
        return res.status(400).json({ error: 'Name und Einpflanzungsdatum sind erforderlich' });
    }

    db.run(`INSERT INTO plants (user_id, name, strain, planted_date, status, substrate, location, notes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, name, strain, planted_date, status, substrate, location, notes], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Pflanze konnte nicht erstellt werden' });
        }

        db.get('SELECT * FROM plants WHERE id = ?', [this.lastID], (err, plant) => {
            if (err) {
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            res.status(201).json(plant);
        });
    });
});

app.put('/api/plants/:id', authenticateToken, (req, res) => {
    const { name, strain, planted_date, status, substrate, location, notes } = req.body;
    const plantId = req.params.id;

    db.run(`UPDATE plants SET name = ?, strain = ?, planted_date = ?, status = ?, 
            substrate = ?, location = ?, notes = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND user_id = ?`,
        [name, strain, planted_date, status, substrate, location, notes, plantId, req.user.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Pflanze konnte nicht aktualisiert werden' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Pflanze nicht gefunden' });
        }

        db.get('SELECT * FROM plants WHERE id = ?', [plantId], (err, plant) => {
            if (err) {
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            res.json(plant);
        });
    });
});

app.delete('/api/plants/:id', authenticateToken, (req, res) => {
    const plantId = req.params.id;

    db.run('DELETE FROM plants WHERE id = ? AND user_id = ?', [plantId, req.user.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Pflanze konnte nicht gelöscht werden' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Pflanze nicht gefunden' });
        }

        res.json({ message: 'Pflanze erfolgreich gelöscht' });
    });
});

// Entries Routes
app.get('/api/entries', authenticateToken, (req, res) => {
    const query = `
        SELECT e.*, p.name as plant_name,
               GROUP_CONCAT(i.filename) as image_filenames
        FROM entries e
        JOIN plants p ON e.plant_id = p.id
        LEFT JOIN images i ON e.id = i.entry_id
        WHERE e.user_id = ?
        GROUP BY e.id
        ORDER BY e.date DESC, e.created_at DESC
    `;

    db.all(query, [req.user.id], (err, entries) => {
        if (err) {
            return res.status(500).json({ error: 'Datenbankfehler' });
        }

        const formattedEntries = entries.map(entry => ({
            ...entry,
            images: entry.image_filenames ? entry.image_filenames.split(',') : []
        }));

        res.json(formattedEntries);
    });
});

app.post('/api/entries', authenticateToken, upload.array('images', 5), (req, res) => {
    const { plant_id, date, watering, water_amount, nutrients, ph_value, height, repotted, issues, notes } = req.body;

    if (!plant_id || !date) {
        return res.status(400).json({ error: 'Pflanze und Datum sind erforderlich' });
    }

    // Prüfen ob Pflanze dem Benutzer gehört
    db.get('SELECT id FROM plants WHERE id = ? AND user_id = ?', [plant_id, req.user.id], (err, plant) => {
        if (err) {
            return res.status(500).json({ error: 'Datenbankfehler' });
        }

        if (!plant) {
            return res.status(404).json({ error: 'Pflanze nicht gefunden' });
        }

        // Eintrag erstellen
        db.run(`INSERT INTO entries (plant_id, user_id, date, watering, water_amount, nutrients, 
                ph_value, height, repotted, issues, notes) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [plant_id, req.user.id, date, watering, water_amount, nutrients, ph_value, height, 
             repotted === 'true' ? 1 : 0, issues, notes], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Eintrag konnte nicht erstellt werden' });
            }

            const entryId = this.lastID;

            // Bilder speichern
            if (req.files && req.files.length > 0) {
                const imagePromises = req.files.map(file => {
                    return new Promise((resolve, reject) => {
                        db.run('INSERT INTO images (entry_id, filename, original_name, file_size, mime_type) VALUES (?, ?, ?, ?, ?)',
                            [entryId, file.filename, file.originalname, file.size, file.mimetype], (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });
                });

                Promise.all(imagePromises)
                    .then(() => {
                        res.status(201).json({ id: entryId, message: 'Eintrag erfolgreich erstellt' });
                    })
                    .catch(err => {
                        res.status(500).json({ error: 'Bilder konnten nicht gespeichert werden' });
                    });
            } else {
                res.status(201).json({ id: entryId, message: 'Eintrag erfolgreich erstellt' });
            }
        });
    });
});

app.delete('/api/entries/:id', authenticateToken, (req, res) => {
    const entryId = req.params.id;

    // Zuerst Bilder löschen
    db.all('SELECT filename FROM images WHERE entry_id = ?', [entryId], (err, images) => {
        if (err) {
            return res.status(500).json({ error: 'Datenbankfehler' });
        }

        // Bilddateien vom Dateisystem löschen
        images.forEach(image => {
            const filePath = path.join(uploadsDir, image.filename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        });

        // Eintrag löschen (Bilder werden durch CASCADE gelöscht)
        db.run('DELETE FROM entries WHERE id = ? AND user_id = ?', [entryId, req.user.id], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Eintrag konnte nicht gelöscht werden' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: 'Eintrag nicht gefunden' });
            }

            res.json({ message: 'Eintrag erfolgreich gelöscht' });
        });
    });
});

// Images Route
app.get('/api/images/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Bild nicht gefunden' });
    }

    res.sendFile(filePath);
});

// Statistics Route
app.get('/api/statistics', authenticateToken, (req, res) => {
    const queries = {
        totalPlants: 'SELECT COUNT(*) as count FROM plants WHERE user_id = ?',
        totalEntries: 'SELECT COUNT(*) as count FROM entries WHERE user_id = ?',
        plantsFlowering: 'SELECT COUNT(*) as count FROM plants WHERE user_id = ? AND status = "flowering"',
        plantsHarvest: 'SELECT COUNT(*) as count FROM plants WHERE user_id = ? AND status = "harvest"'
    };

    const stats = {};
    let completed = 0;
    const total = Object.keys(queries).length;

    Object.keys(queries).forEach(key => {
        db.get(queries[key], [req.user.id], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            
            stats[key] = result.count;
            completed++;
            
            if (completed === total) {
                // Durchschnittliche Wachstumstage berechnen
                db.all('SELECT planted_date FROM plants WHERE user_id = ?', [req.user.id], (err, plants) => {
                    if (err) {
                        return res.status(500).json({ error: 'Datenbankfehler' });
                    }
                    
                    let avgGrowthDays = 0;
                    if (plants.length > 0) {
                        const totalDays = plants.reduce((sum, plant) => {
                            const plantedDate = new Date(plant.planted_date);
                            const today = new Date();
                            const daysDiff = Math.floor((today - plantedDate) / (1000 * 60 * 60 * 24));
                            return sum + daysDiff;
                        }, 0);
                        avgGrowthDays = Math.round(totalDays / plants.length);
                    }
                    
                    stats.avgGrowthDays = avgGrowthDays;
                    res.json(stats);
                });
            }
        });
    });
});

// Error Handler
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'Datei zu groß (max. 5MB)' });
        }
    }
    
    res.status(500).json({ error: 'Interner Serverfehler' });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpunkt nicht gefunden' });
});

// Server starten
app.listen(PORT, () => {
    console.log(`🌿 Cannabis Tagebuch Server läuft auf Port ${PORT}`);
    console.log(`📊 Admin-Panel: http://localhost:${PORT}/admin`);
    console.log(`🔑 Standard-Login: demo / demo123`);
});

// Graceful Shutdown
process.on('SIGINT', () => {
    console.log('\n🔄 Server wird heruntergefahren...');
    db.close((err) => {
        if (err) {
            console.error('Fehler beim Schließen der Datenbank:', err);
        } else {
            console.log('✅ Datenbankverbindung geschlossen');
        }
        process.exit(0);
    });
});

module.exports = app;