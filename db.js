const mongoose = require('mongoose');

class DocumentCollection {
  constructor(name) {
    this.name = name;
    this.data = [];
  }

  // Pure MongoDB mode: no disk JSON loaded
  load() {}
  save() {}

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
      this.data = docs;
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
    const item = this.data.find(d => String(d.id || d._id) === String(id));
    return item ? { ...item } : null;
  }

  insertOne(doc) {
    const id = doc.id || doc._id || (this.data.length > 0 ? Math.max(...this.data.map(d => Number(d.id) || 0)) + 1 : 1);
    const newDoc = {
      ...doc,
      id,
      _id: String(id),
      createdAt: doc.createdAt || new Date().toISOString()
    };
    this.data.push(newDoc);

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

  updateOne(predicate, updates) {
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

    // Direct update to MongoDB Atlas
    if (mongoose.connection && mongoose.connection.readyState === 1) {
      mongoose.connection.db.collection(this.name).replaceOne(
        { _id: updated._id },
        updated,
        { upsert: true }
      ).catch(err => {
        console.warn(`[MongoDB] Error updating ${this.name}:`, err.message);
      });
    }

    return { ...updated };
  }

  updateById(id, updates) {
    return this.updateOne({ id: Number(id) || id }, updates);
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
  systemConfigs: getCollection('systemConfigs')
};
