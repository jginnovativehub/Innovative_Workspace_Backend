const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
  } catch (err) {
    // Silent ignore in read-only setups
  }
}

class DocumentCollection {
  constructor(name) {
    this.name = name;
    this.data = [];
    this.deletedIds = new Set();
    this.filePath = path.join(dataDir, `${name}.json`);
    this.load();
  }

  // File fallback for offline / development / in-memory mode
  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) {
            this.data = parsed;
          }
        }
      }
    } catch (err) {
      // Fallback cleanly to in-memory array
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (err) {
      // Fallback silently if disk is unwritable
    }
  }

  // Live direct query from MongoDB Atlas
  async syncFromMongo() {
    if (!mongoose.connection) return this.data;
    if (mongoose.connection.readyState === 2) {
      // If currently connecting, wait briefly for connection to be ready
      for (let i = 0; i < 25; i++) {
        if (mongoose.connection.readyState === 1) break;
        await new Promise(r => setTimeout(r, 200));
      }
    }
    if (mongoose.connection.readyState !== 1) return this.data;
    try {
      const atlasCollection = mongoose.connection.db.collection(this.name);
      const docs = await atlasCollection.find().toArray();

      // Index current memory docs so local readAt and updates aren't wiped out by Mongo replication lag
      const existingMap = new Map();
      for (const item of this.data) {
        if (item.id !== undefined && item.id !== null) existingMap.set(String(item.id), item);
        if (item._id) existingMap.set(String(item._id), item);
      }

      this.data = docs
        .filter(d => {
          // Never resurrect dismissed notifications
          if (this.deletedIds.has(String(d.id)) || this.deletedIds.has(String(d._id))) return false;
          return true;
        })
        .map((d, idx) => {
          const idKey = d.id !== undefined && d.id !== null ? String(d.id) : (d._id ? String(d._id) : String(idx + 1));
          const local = existingMap.get(idKey);
          // Preserve readAt if marked read locally
          const readAt = d.readAt || (local ? local.readAt : undefined);
          return {
            ...d,
            readAt,
            id: d.id !== undefined && d.id !== null ? (Number(d.id) || d.id) : (d._id ? String(d._id) : idx + 1),
            _id: d._id ? String(d._id) : String(d.id || idx + 1)
          };
        });

      // Update local cache
      this.save();
      return this.data;
    } catch (err) {
      console.warn(`[MongoDB Sync] Error fetching ${this.name}:`, err.message);
      return this.data;
    }
  }

  find(predicate = null) {
    if (!predicate) return [...this.data];
    return this.data.filter(item => {
      for (const [key, val] of Object.entries(predicate)) {
        if (typeof val === 'object' && val !== null) {
          if ('$in' in val && Array.isArray(val.$in)) {
            if (!val.$in.includes(item[key])) return false;
          } else if ('$ne' in val) {
            if (item[key] === val.$ne) return false;
          }
        } else {
          if (item[key] !== val) return false;
        }
      }
      return true;
    });
  }

  findOne(predicate) {
    const results = this.find(predicate);
    return results.length > 0 ? { ...results[0] } : null;
  }

  findById(id) {
    if (id === undefined || id === null || id === 'undefined' || id === 'null' || id === '') return null;
    const strId = String(id).trim();
    const numId = Number(strId);
    const item = this.data.find(d => {
      if (d.id !== undefined && d.id !== null) {
        if (String(d.id) === strId) return true;
        if (!isNaN(numId) && Number(d.id) === numId) return true;
      }
      if (d._id !== undefined && d._id !== null) {
        if (String(d._id) === strId) return true;
      }
      return false;
    });
    return item ? { ...item } : null;
  }

  insertOne(doc) {
    let nextId = 1;
    for (const d of this.data) {
      const num = Number(d.id);
      if (!isNaN(num) && num >= nextId) {
        nextId = num + 1;
      }
    }
    const id = doc.id !== undefined && doc.id !== null ? (Number(doc.id) || doc.id) : nextId;
    const newDoc = {
      ...doc,
      id,
      _id: doc._id ? String(doc._id) : String(id),
      createdAt: doc.createdAt || new Date().toISOString()
    };
    this.data.push(newDoc);
    this.save();

    // Direct write to MongoDB Atlas
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      mongoose.connection.db.collection(this.name).replaceOne(
        { _id: newDoc._id },
        newDoc,
        { upsert: true }
      ).catch(err => {
        console.warn(`[MongoDB] Error inserting into ${this.name}:`, err.message);
      });
    }

    return { ...newDoc };
  }

  insertMany(docs) {
    return docs.map(d => this.insertOne(d));
  }

  async updateOne(predicate, updates) {
    const index = this.data.findIndex(item => {
      for (const [key, val] of Object.entries(predicate)) {
        if (item[key] !== val) return false;
      }
      return true;
    });

    if (index === -1) return null;

    const existing = this.data[index];
    const updated = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.data[index] = updated;
    this.save();

    // Direct update to MongoDB Atlas
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      try {
        const orFilters = [];
        if (updated._id) {
          orFilters.push({ _id: updated._id });
          if (mongoose.Types.ObjectId.isValid(updated._id)) {
            orFilters.push({ _id: new mongoose.Types.ObjectId(updated._id) });
          }
        }
        if (updated.id !== undefined && updated.id !== null) {
          orFilters.push({ id: updated.id });
          const num = Number(updated.id);
          if (!isNaN(num)) orFilters.push({ id: num });
        }
        const mongoFilter = orFilters.length > 0 ? { $or: orFilters } : { _id: updated._id };
        await mongoose.connection.db.collection(this.name).updateOne(
          mongoFilter,
          { $set: { ...updates, updatedAt: updated.updatedAt } }
        );
      } catch (err) {
        console.warn(`[MongoDB] Error updating ${this.name}:`, err.message);
      }
    }

    return { ...updated };
  }

  async updateById(id, updates) {
    if (id === undefined || id === null || id === 'undefined' || id === 'null' || id === '') return null;
    const strId = String(id).trim();
    const numId = Number(strId);
    const index = this.data.findIndex(d => {
      if (d.id !== undefined && d.id !== null) {
        if (String(d.id) === strId) return true;
        if (!isNaN(numId) && Number(d.id) === numId) return true;
      }
      if (d._id !== undefined && d._id !== null) {
        if (String(d._id) === strId) return true;
      }
      return false;
    });

    if (index === -1) return null;

    const existing = this.data[index];
    const updated = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.data[index] = updated;
    this.save();

    // Direct update to MongoDB Atlas
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      try {
        const orFilters = [];
        if (updated._id) {
          orFilters.push({ _id: updated._id });
          if (mongoose.Types.ObjectId.isValid(updated._id)) {
            orFilters.push({ _id: new mongoose.Types.ObjectId(updated._id) });
          }
        }
        if (updated.id !== undefined && updated.id !== null) {
          orFilters.push({ id: updated.id });
          const num = Number(updated.id);
          if (!isNaN(num)) orFilters.push({ id: num });
        }
        const mongoFilter = orFilters.length > 0 ? { $or: orFilters } : { _id: updated._id };
        await mongoose.connection.db.collection(this.name).updateOne(
          mongoFilter,
          { $set: { ...updates, updatedAt: updated.updatedAt } }
        );
      } catch (err) {
        console.warn(`[MongoDB] Error updating ${this.name}:`, err.message);
      }
    }

    return { ...updated };
  }

  deleteOne(predicate) {
    const index = this.data.findIndex(item => {
      for (const [key, val] of Object.entries(predicate)) {
        if (key === '$or' && Array.isArray(val)) {
          const anyMatch = val.some(cond => {
            return Object.entries(cond).every(([k, v]) => String(item[k]) === String(v));
          });
          if (!anyMatch) return false;
        } else {
          if (String(item[key]) !== String(val)) return false;
        }
      }
      return true;
    });

    if (index === -1) return false;
    const removed = this.data.splice(index, 1)[0];
    if (removed) {
      if (removed.id !== undefined && removed.id !== null) this.deletedIds.add(String(removed.id));
      if (removed._id) this.deletedIds.add(String(removed._id));
      this.save();
    }

    // Direct delete from MongoDB Atlas
    if (mongoose.connection && mongoose.connection.readyState === 1 && removed) {
      const orFilters = [];
      if (removed._id) {
        orFilters.push({ _id: removed._id });
        if (mongoose.Types.ObjectId.isValid(removed._id)) {
          orFilters.push({ _id: new mongoose.Types.ObjectId(removed._id) });
        }
      }
      if (removed.id !== undefined && removed.id !== null) {
        orFilters.push({ id: removed.id });
        const num = Number(removed.id);
        if (!isNaN(num)) orFilters.push({ id: num });
      }

      const mongoFilter = orFilters.length > 0 ? { $or: orFilters } : { _id: removed._id };
      mongoose.connection.db.collection(this.name).deleteOne(mongoFilter).catch(err => {
        console.warn(`[MongoDB] Error deleting from ${this.name}:`, err.message);
      });
    }

    return true;
  }

  deleteById(id) {
    const num = Number(id);
    const orConditions = [
      { id: id },
      { _id: String(id) }
    ];
    if (!isNaN(num)) {
      orConditions.push({ id: num });
    }
    return this.deleteOne({
      $or: orConditions
    });
  }

  count(predicate = null) {
    return this.find(predicate).length;
  }

  clear() {
    this.data = [];
    this.deletedIds.clear();
    this.save();
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      mongoose.connection.db.collection(this.name).deleteMany({}).catch(err => {
        console.warn(`[MongoDB] Error clearing ${this.name}:`, err.message);
      });
    }
  }
}

const collections = {};

function getCollection(name) {
  if (!collections[name]) {
    collections[name] = new DocumentCollection(name);
  }
  return collections[name];
}

async function syncAllWithMongo() {
  if (!mongoose.connection || mongoose.connection.readyState !== 1) return;
  try {
    for (const collName of Object.keys(collections)) {
      const col = collections[collName];
      try {
        const atlasCollection = mongoose.connection.db.collection(collName);
        const atlasDocs = await atlasCollection.find().toArray();
        col.data = atlasDocs;
      } catch (err) {
        console.warn(`[MongoDB] Sync notice on ${collName}:`, err.message);
      }
    }
    console.log('[MongoDB] Synced all collections directly from MongoDB Atlas');
  } catch (outerErr) {
    console.warn('[MongoDB] Sync notice:', outerErr.message);
  }
}

module.exports = {
  getCollection,
  syncAllWithMongo,
  users: getCollection('users'),
  projects: getCollection('projects'),
  projectMemberships: getCollection('projectMemberships'),
  milestones: getCollection('milestones'),
  milestoneDependencies: getCollection('milestoneDependencies'),
  tasks: getCollection('tasks'),
  taskDependencies: getCollection('taskDependencies'),
  progressUpdates: getCollection('progressUpdates'),
  weeklyReports: getCollection('weeklyReports'),
  weeklyReportVersions: getCollection('weeklyReportVersions'),
  reviewDecisions: getCollection('reviewDecisions'),
  scheduleRequests: getCollection('scheduleRequests'),
  auditEvents: getCollection('auditEvents'),
  notifications: getCollection('notifications'),
  badges: getCollection('badges'),
  userBadges: getCollection('userBadges'),
  systemConfigs: getCollection('systemConfigs'),
  personalProjects: getCollection('personalProjects')
};
