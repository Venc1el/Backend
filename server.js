const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const mime = require("mime-types");
const moment = require('moment-timezone');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary')
const port = process.env.PORT || 3306;

require('dotenv').config();
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "https://jambangan.vercel.app",
    methods: ["POST", "GET", "PUT", "DELETE", "PATCH"],
    credentials: true,
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept"],
  })
);


const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true,
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'images', // Specify the folder in Cloudinary where you want to upload the images
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
        // Optional: Add other Cloudinary upload options here
    },
});

//Verifikasi user / akun
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: "Token is required, please provide a token" });
    } else {
        // Verify the token
        jwt.verify(token, "your-secret-key", (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "Token has expired or is invalid" });
            } else {
                req.id = decoded.id;
                req.name = decoded.name;
                req.level = decoded.level;
                next();
            }
        });
    }
};

const verifyUserAdmin = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: "Token is required, please provide a token" });
    } else {
        // Verify the token
        jwt.verify(token, "your-secret-key", (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "Token has expired or is invalid" });
            } else {
                if (decoded.level === "Admin") {
                    req.id = decoded.id;
                    req.name = decoded.name;
                    req.level = decoded.level;
                    next();
                } else {
                    return res.status(403).json({ message: "Access denied. Admin privileges required" });
                }
            }
        });
    }
};


//Get User / Akun
app.get("/users", verifyUserAdmin, (req, res) => {
    db.query("SELECT * FROM tbluser", (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        return res.status(200).json(data);
    });
});

app.get("/users/:userId/hasposts", verifyUserAdmin, (req, res) => {
    const userId = req.params.userId;

    db.query("SELECT COUNT(*) AS postCount FROM tblcomplaints WHERE iduser = ?", [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        const postCount = result[0].postCount;

        return res.status(200).json({ hasPosts: postCount > 0 });
    });
});


// Delete User
app.delete("/users/:id", verifyUserAdmin, (req, res) => {
    const userId = req.params.id;

    db.query("DELETE FROM tbluser WHERE iduser = ?", [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        return res.status(200).json({ message: "User deleted successfully" });
    });
});

//Tambah user / akun
app.post("/users", verifyUserAdmin, async (req, res) => {
    const { username, password, level, aktif } = req.body;

    // Check if the username already exists in the database
    db.query("SELECT * FROM tbluser WHERE username = ?", [username], async (err, existingUser) => {
        if (err) {
            return res.status(500).json({ message: "Server error" });
        }

        if (existingUser.length > 0) {
            return res.status(400).json({ message: "Username already exists. Choose a different username." });
        }

        // If the username doesn't exist, proceed to add the new user
        const newUser = {
            username,
            // Hash the password before storing it
            password: await bcrypt.hash(password, 10), // Use bcrypt to hash the password
            level,
            aktif,
        };

        db.query("INSERT INTO tbluser SET ?", newUser, (err) => {
            if (err) {
                return res.status(500).json({ message: "Server error" });
            }
            return res.status(201).json({ message: "User created successfully" });
        });
    });
});

// Update User
app.put("/users/:id", verifyUserAdmin, (req, res) => {
    const userId = req.params.id;
    const { username, password } = req.body;

    // Check if the username already exists in the database (excluding the current user)
    db.query("SELECT * FROM tbluser WHERE username = ? AND iduser <> ?", [username, userId], async (err, existingUser) => {
        if (err) {
            return res.status(500).json({ message: "Server error" });
        }

        if (existingUser.length > 0) {
            return res.status(400).json({ message: "Username already exists. Choose a different username." });
        }

        const updatedUser = {
            username,
        };

        // Check if a new password is provided
        if (password) {
            // Hash the new password
            bcrypt.hash(password, 10, (err, hashedPassword) => {
                if (err) {
                    console.error("Error hashing password:", err);
                    return res.status(500).json({ message: "Server Error" });
                }

                updatedUser.password = hashedPassword;

                // Update the user's data in the database
                db.query(
                    "UPDATE tbluser SET ? WHERE iduser = ?",
                    [updatedUser, userId],
                    (err) => {
                        if (err) {
                            console.error("Error updating user:", err);
                            return res.status(500).json({ message: "Server Error" });
                        } else {
                            return res.status(200).json({ message: "User updated successfully" });
                        }
                    }
                );
            });
        } else {
            // If no new password is provided, update only the username
            db.query(
                "UPDATE tbluser SET ? WHERE iduser = ?",
                [updatedUser, userId],
                (err) => {
                    if (err) {
                        console.error("Error updating user:", err);
                        return res.status(500).json({ message: "Server Error" });
                    } else {
                        return res.status(200).json({ message: "User updated successfully" });
                    }
                }
            );
        }
    });
});



//--------------------------------MAPS----------------------------------
app.get('/maps', (req, res) => {
    const sql = 'SELECT * FROM tblmaps';

    db.query(sql, (err, result) => {
        if (err) {
            console.error('Error fetching map data:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ mapsData: result });
    });
});



//-----------------------------------ADUAN---------------------------------------
const upload = multer({ storage: storage });

app.get("/complaints", verifyUserAdmin, (req, res) => {
    const userId = req.params.userId;

    db.query(` SELECT 
            tblcomplaints.idcomplaint, 
            tblcomplaints.type, 
            tblcomplaints.text, 
            tblcomplaints.alamat, 
            tblcomplaints.image_url, 
            tblcomplaints.date, 
            tblcomplaints.status,
            tbluser.iduser,
            tbluser.username 
        FROM tblcomplaints
        JOIN tbluser ON tblcomplaints.iduser = tbluser.iduser`,[userId], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        return res.status(200).json(data);
    });
});

app.get("/complaints/:id", verifyUser, (req, res) => {
    const complaintId = req.params.id;

    db.query("SELECT * FROM tblcomplaints WHERE idcomplaint = ?", [complaintId], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        if (data.length === 0) {
            return res.status(404).json({ message: "Complaint not found" });
        }

        return res.status(200).json(data[0]);
    });
});


// Add a new endpoint to retrieve report data for a specific user
app.get("/reportData/:iduser", verifyUser, (req, res) => {
    const iduser = req.id;

    // Query to get the total reports for the specified user
    const totalReportsQuery = `
        SELECT COUNT(*) AS totalReports
        FROM tblcomplaints
        WHERE iduser = ?;
    `;

    // Query to get the responded reports for the specified user
    const respondedReportsQuery = `
        SELECT COUNT(*) AS respondedReports
        FROM tblcomplaints
        WHERE iduser = ? AND status != 'Menunggu Respon';
    `;

    // Execute both queries in parallel
    db.query(totalReportsQuery, [iduser], (err, totalReportsResult) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        db.query(respondedReportsQuery, [iduser], (err, respondedReportsResult) => {
            if (err) {
                return res.status(500).json({ message: "Server Error" });
            }

            // Extract the counts from the results
            const totalReports = totalReportsResult[0].totalReports;
            const respondedReports = respondedReportsResult[0].respondedReports;

            return res.status(200).json({ totalReports, respondedReports });
        });
    });
});



app.get("/reportData", verifyUserAdmin, (req, res) => {
    db.query("SELECT COUNT(*) AS totalReports FROM tblcomplaints", (err, totalReports) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        db.query("SELECT COUNT(*) AS respondedReports FROM tblcomplaints WHERE status != 'Menunggu Respon'", (err, respondedReports) => {
            if (err) {
                return res.status(500).json({ message: "Server Error" });
            }

            return res.status(200).json({ totalReports: totalReports[0].totalReports, respondedReports: respondedReports[0].respondedReports });
        });
    });
});

app.get("/complaint_responses", verifyUserAdmin, (req, res) => {
    // Query the database to get all columns from tblcomplaint_responses
    db.query("SELECT * FROM tblcomplaint_responses", (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Server error" });
        }

        // Return the response records
        return res.status(200).json({ responses: results });
    });
});



app.get("/complaints/:complaintId/responses", verifyUser, async (req, res) => {
    const { complaintId } = req.params;

    // Query the database to get responses for the specified complaint ID
    db.query(
        "SELECT * FROM tblcomplaint_responses WHERE complaint_id = ?",
        [complaintId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Server error" });
            }

            // Return the response records
            return res.status(200).json({ responses: results });
        }
    );
});

app.get("/maps/all", (req, res) => {
    db.query("SELECT coordinates, popup_content FROM tblmaps", (err, results) => {
        if (err) {
            console.error("Error fetching coordinates:", err);
            return res.status(500).json({ message: "Server error" });
        }

        // Initialize an array to store all coordinates and popup_content
        const allData = [];

        // Loop through the results and parse each JSON string into an object
        for (const result of results) {
            if (result.coordinates) {
                const data = {
                    coordinates: JSON.parse(result.coordinates),
                    popup_content: result.popup_content,
                };
                allData.push(data);
            }
        }

        // Now, send the response with the expected structure
        return res.status(200).json({ coordinates: allData });
    });
});

app.get('/maps/user/:id', verifyUser, (req, res) => {
    const userId = req.id;
    const query = `
        SELECT m.coordinates, m.popup_content
        FROM tblmaps AS m
        JOIN tblcomplaints AS c ON m.complaint_id = c.idcomplaint
        WHERE c.iduser = ?
    `;

    db.query(query, [userId], (error, results) => {
        if (error) {
            console.error('Error fetching user-specific map data:', error);
            res.status(500).json({ error: 'Internal Server Error' });
        } else {
            // Initialize an array to store formatted coordinates and popup_content
            const formattedResults = [];

            // Loop through the results and parse each JSON string into an object
            for (const result of results) {
                if (result.coordinates) {
                    const coordinates = JSON.parse(result.coordinates);
                    const formattedData = {
                        coordinates,
                        popup_content: result.popup_content
                    };
                    formattedResults.push(formattedData);
                }
            }

            // Now, send the response with the expected structure
            res.status(200).json({ coordinates: formattedResults });
        }
    });
});




// Route to insert complaints and map data
app.post(
    "/complaints",
    verifyUser,
    upload.single("image"),
    async (req, res) => {
        const { text, type, status, alamat, popup_content, coordinates, keterangan } = req.body;
        const imageUrl = req.file.path;
        const date = moment().tz('Asia/Jakarta').format('YYYY-MM-DD HH:mm:ss');
        const userId = req.id;

        const newComplaint = {
            text,
            alamat,
            image_url: imageUrl,
            type,
            status,
            date,
            keterangan,
            iduser: userId,
        };

        try {
            // Insert the complaint into tblcomplaints
            db.query("INSERT INTO tblcomplaints SET ?", newComplaint, (err, result) => {
                if (err) {
                    console.error("Error inserting complaint:", err);
                    return res.status(500).json({ message: "Server error" });
                }

                const lastInsertId = result.insertId; // Get the last insert ID

                // Insert map data into tblmaps and associate it with the complaint
                db.query("INSERT INTO tblmaps (complaint_id, popup_content, coordinates) VALUES (?, ?, ?)",
                    [lastInsertId, popup_content, coordinates], (err) => {
                        if (err) {
                            console.error("Error inserting map data:", err);
                            return res.status(500).json({ message: "Server error" });
                        }

                        return res
                            .status(201)
                            .json({ message: "Complaint and map data submitted successfully", lastInsertId });
                    });
            });
        } catch (error) {
            console.error("Error submitting complaint and map data:", error);
            return res.status(500).json({ message: "Server error" });
        }
    }
);



app.post(
    "/complaints/:complaintId/responses",
    verifyUser,
    upload.single("image_url"),
    async (req, res) => {
        const { complaintId } = req.params;
        const { text, status } = req.body;
        const image_url = req.file.path;
        const date = new Date().toISOString();

        const newResponse = {
            complaint_id: complaintId,
            text,
            image_url,
            date_responses: date,
        }

        db.query("INSERT INTO tblcomplaint_responses SET ?", newResponse, (err) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Server error" });
            }

            if (status) {
                db.query(
                    "UPDATE tblcomplaints SET status = ? WHERE idcomplaint = ?",
                    [status, complaintId],
                    (err) => {
                        if (err) {
                            console.error("Database error:", err);
                            return res.status(500).json({ error: "Server error" });
                        }
                        return res.status(201).json({ message: "Response and status updated successfully" });
                    }
                )
            } else {
                return res.status(201).json({ message: "Response added successfully" });
            }
        });
    }
)



app.get("/uploads/:filename", (req, res) => {
    const { filename } = req.params;
    res.sendFile(path.join(__dirname, "public/images", filename));
});


//-----------------------------UMKM-------------------

app.get("/umkm/posts", verifyUser, (req, res) => {
    db.query("SELECT * FROM tblumkm ", (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        return res.status(200).json(data);
    });
});

app.get("/umkm/:id", (req, res) => {
    const id = req.params.id;

    db.query("SELECT * FROM tblumkm WHERE id = ?", [id], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        if (data.length === 0) {
            return res.status(404).json({ message: "UMKM not found" });
        }
        return res.status(200).json(data[0]);
    });
});

app.delete("/umkm/:id", verifyUserAdmin, (req, res) => {
    const id = req.params.id;

    db.query("DELETE FROM tblumkm WHERE id = ?", [id], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "POsts not found" });
        }

        return res.status(200).json({ message: "Posts deleted successfully" });
    });
});

app.post("/posts", verifyUser, upload.single("image"), (req, res) => {
    const { content, kategori, judul, alamat } = req.body;
    const image = req.file.path;

    const newPost = {
        content,
        kategori,
        judul,
        alamat,
        isApproved: false,
        image,
    }

    try {
        db.query("INSERT INTO tblumkm SET ?", newPost, (err) => {
            if (err) {
                console.error("Error inserting post:", err);
                return res.status(500).json({ message: "Server Error" })
            }

            return res.status(201).json({ message: "Posts submitted for review" })
        })
    } catch (error) {
        console.error('error submiting post', error)
        return res.status(500).json({ message: "Server Error" })
    }
})

app.put("/umkm/posts/:id", verifyUserAdmin, upload.single("image"), (req, res) => {
    const postId = req.params.id;
    const updatedPost = {
        judul: req.body.judul,
        content: req.body.content,
        alamat: req.body.alamat,
        kategori: req.body.kategori,
    };

    // Check if a new image is uploaded
    if (req.file) {
        updatedPost.image = req.file.path;
    }

    db.query(
        "UPDATE tblumkm SET ? WHERE id = ?",
        [updatedPost, postId],
        (err) => {
            if (err) {
                return res.status(500).json({ message: "Server Error" });
            } else {
                return res.status(200).json({ message: "Post Updated Successfully" });
            }
        }
    );
});


app.patch("/umkm/posts/:id/approve", verifyUserAdmin, (req, res) => {
    const postId = req.params.id

    db.query(
        "UPDATE tblumkm SET isApproved = ? WHERE id = ? ",
        [true, postId],
        (err) => {
            if (err) {
                return res.status(500).json({ message: "Server Error" })
            } else {
                return res.status(200).json({ message: "Post approved succesfully" })
            }
        }
    )
})

app.patch("/umkm/posts/:id/take-down", verifyUserAdmin, (req, res) => {
    const postId = req.params.id;

    db.query(
        "UPDATE tblumkm SET isApproved = ? WHERE id = ?",
        [false, postId],
        (err) => {
            if (err) {
                return res.status(500).json({ message: "Server Error" });
            } else {
                return res.status(200).json({ message: "Post taken down successfully" });
            }
        }
    );
});

//-----------------------------------LOGIN------------------------------------

app.get("/", verifyUser, (req, res) => {
    return res.json({ status: "Success", id: req.id, name: req.name, level: req.level });
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // Find the user by username in the database (case-sensitive)
    db.query("SELECT * FROM tbluser WHERE BINARY username = ?", [username], async (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }

        if (data.length === 0) {
            // User not found
            return res.status(401).json({ message: "User not found." });
        }
        const user = data[0];
        const hashedPassword = user.password;

        // Compare the provided password with the stored hash
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (passwordMatch) {
            // Passwords match, generate a JWT token
            const token = jwt.sign({ id: user.iduser, name: user.username, level: user.level }, "your-secret-key", {
                expiresIn: "8h",
            });

            // Use res.cookie() to set the cookie
            res.cookie("token", token, {
                httpOnly: true,
                secure: true, // Set to true if your app is served over HTTPS
                sameSite: "None", // Required for cross-origin cookies
                domain: "https://frontend-jambangan.vercel.app",
                maxAge: 8 * 60 * 60 * 1000, // Use your custom domain here
            });

            // Update the 'aktif' status to 1 here
            db.query("UPDATE tbluser SET aktif = 1 WHERE iduser = ?", [user.iduser], (updateErr) => {
                if (updateErr) {
                    return res.status(500).json({ message: "Server Error" });
                }

                return res.json({ status: "Success", level: user.level, token });
            });
        } else {
            // Incorrect username or password
            return res.status(401).json({ message: "Incorrect username or password." });
        }
    });
});



app.get("/logout", verifyUser, (req, res) => {
    const userId = req.id;

    // Update aktif to 0 to indicate the user is offline
    db.query("UPDATE tbluser SET aktif = 0 WHERE iduser = ?", [userId], (updateErr, results) => {
        if (updateErr) {
            return res.status(500).json({ message: "Server Error" });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.clearCookie("token");
        return res.json({ status: "Success" });
    });
});
//------------------FOR SPECIFIC USERS-------------------------
// Get complaints for a specific user
app.get("/complaints/user/:userId", verifyUser, (req, res) => {
    const userId = req.params.userId;

    const query = `
        SELECT 
            tblcomplaints.idcomplaint, 
            tblcomplaints.type, 
            tblcomplaints.text, 
            tblcomplaints.alamat, 
            tblcomplaints.image_url, 
            tblcomplaints.date, 
            tblcomplaints.status,
            tbluser.iduser,
            tbluser.username 
        FROM tblcomplaints
        JOIN tbluser ON tblcomplaints.iduser = tbluser.iduser
        WHERE tblcomplaints.iduser = ?;  -- Filter by user ID
    `;

    db.query(query, [userId], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        return res.status(200).json(data);
    });
});



//---------------------PUBLICS----------------------------
app.get("/public/posts", (req, res) => {
    db.query("SELECT * FROM tblumkm WHERE isApproved = ?", [true], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        return res.status(200).json(data);
    });
});

// Get details of a specific post by ID from the public/posts route
app.get("/public/posts/:postId", (req, res) => {
    const postId = req.params.postId;

    db.query("SELECT * FROM tblumkm WHERE id = ? AND isApproved = ?", [postId, true], (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Server Error" });
        }
        if (data.length === 0) {
            return res.status(404).json({ message: "Post not found" });
        }

        return res.status(200).json(data[0]);
    });
});


app.listen(port, () => {
    console.log("server is listening");
});
