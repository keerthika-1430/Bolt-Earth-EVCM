// ═══════════════════════════════════════════════════════════════
//  BOLT EARTH — MongoDB Atlas Schema Design
//  Database: boltearth
// ═══════════════════════════════════════════════════════════════

// ── Collection: users ──────────────────────────────────────────
{
  "_id": ObjectId("..."),
  "name": "Arjun Kumar",
  "email": "arjun@example.com",
  "password": "$2b$12$...",        // bcrypt hashed, NEVER store plain text
  "created_at": ISODate("2024-01-15T10:00:00Z")
}

// Index: { "email": 1 }, unique: true
// This prevents duplicate accounts and speeds up login lookups


// ── Collection: bookings ───────────────────────────────────────
{
  "_id": ObjectId("..."),
  "user_id": "string_of_user_objectid",   // links to users._id
  "user_email": "arjun@example.com",       // denormalized for fast queries
  "user_name": "Arjun Kumar",
  "station_name": "Bolt Earth — Anna Nagar",
  "slot_id": "SL0900",
  "slot_time": "09:00",
  "charging_mode": "fast",                 // "fast" | "slow"
  "duration_min": 25,
  "cost": 15.0,
  "token": "EV7K2MNX",                    // unique booking token
  "status": "confirmed",                   // "confirmed" | "completed" | "cancelled"
  "booked_at": ISODate("2024-01-15T10:05:00Z")
}

// Indexes:
//   { "user_email": 1 }            — fast user-specific queries
//   { "token": 1 }, unique: true   — token lookup
//   { "status": 1 }                — filter active bookings


// ── Collection: history ────────────────────────────────────────
// Mirror of bookings, kept for audit/analytics even after cancellation
{
  "_id": ObjectId("..."),
  "booking_id": "string_of_booking_objectid",
  "user_id": "...",
  "user_email": "arjun@example.com",
  "user_name": "Arjun Kumar",
  "station_name": "Bolt Earth — Anna Nagar",
  "slot_id": "SL0900",
  "slot_time": "09:00",
  "charging_mode": "fast",
  "duration_min": 25,
  "cost": 15.0,
  "token": "EV7K2MNX",
  "status": "confirmed",
  "booked_at": ISODate("2024-01-15T10:05:00Z")
}

// Index: { "user_email": 1, "booked_at": -1 }  — latest history first


// ═══════════════════════════════════════════════════════════════
//  Atlas Setup Steps
// ═══════════════════════════════════════════════════════════════
//
//  1. Go to https://cloud.mongodb.com
//  2. Create a FREE M0 cluster (512MB, sufficient for dev)
//  3. Under "Database Access" → Add user with readWrite on "boltearth"
//  4. Under "Network Access" → Allow 0.0.0.0/0 (or your server IP)
//  5. Click "Connect" → "Drivers" → Copy your connection string
//  6. Replace the MONGO_URI in app.py or set env var:
//
//     export MONGO_URI="mongodb+srv://username:password@cluster.mongodb.net/boltearth?retryWrites=true&w=majority"
//
//  7. Indexes are created automatically when the app starts.
