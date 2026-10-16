import { MongoClient, Db, ObjectId, GridFSBucket } from "mongodb";

const uri = process.env.MONGODB_URI || process.env.MONGO_URL || "mongodb://127.0.0.1:27017/mailforge";

let client: MongoClient;
let clientPromise: Promise<MongoClient>;

declare global {
  // eslint-disable-next-line no-var
  var _mongoClientPromise: Promise<MongoClient> | undefined;
}

export function isMongoConfigured(): boolean {
  return Boolean(process.env.MONGODB_URI || process.env.MONGO_URL);
}

if (process.env.NODE_ENV === "development") {
  // In development mode, use a global variable so the MongoClient is not repeatedly instantiated
  if (!global._mongoClientPromise) {
    client = new MongoClient(uri, {
      connectTimeoutMS: 5000,
      serverSelectionTimeoutMS: 5000,
    });
    global._mongoClientPromise = client.connect().catch((err) => {
      console.warn("MongoDB connection notice (dev fallback active):", err.message);
      return client;
    });
  }
  clientPromise = global._mongoClientPromise;
} else {
  // In production mode, avoid global variable
  client = new MongoClient(uri, {
    connectTimeoutMS: 5000,
    serverSelectionTimeoutMS: 5000,
  });
  clientPromise = client.connect().catch((err) => {
    console.warn("MongoDB production connection notice:", err.message);
    return client;
  });
}

export async function getMongoClient(): Promise<MongoClient> {
  return await clientPromise;
}

export async function getMongoDb(dbName?: string): Promise<Db> {
  const c = await getMongoClient();
  return c.db(dbName || "mailforge");
}

export interface StoredTemplateImageDoc {
  _id?: ObjectId;
  userId: string;
  folder: string; // e.g. "General", "Newsletters", "Banners", "Promotions"
  filename: string;
  contentType: string;
  size: number;
  dataBase64: string; // Base64 image data for fast zero-config rendering
  url?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Save an uploaded image into MongoDB's template_images collection
 */
export async function saveTemplateImageToMongo(params: {
  userId: string;
  folder?: string;
  filename: string;
  contentType: string;
  size: number;
  dataBase64: string;
}): Promise<{ id: string; url: string; folder: string; filename: string }> {
  const db = await getMongoDb();
  const collection = db.collection<StoredTemplateImageDoc>("template_images");

  const folder = (params.folder || "general").trim();
  const docToInsert: StoredTemplateImageDoc = {
    userId: params.userId,
    folder,
    filename: params.filename,
    contentType: params.contentType,
    size: params.size,
    dataBase64: params.dataBase64,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  const result = await collection.insertOne(docToInsert as any);
  const id = result.insertedId.toString();
  const url = `/api/templates/images/${id}`;

  await collection.updateOne({ _id: result.insertedId }, { $set: { url } });

  return {
    id,
    url,
    folder,
    filename: params.filename,
  };
}

/**
 * Retrieve user's template images from MongoDB, optionally filtered by folder
 */
export async function getTemplateImagesFromMongo(
  userId: string,
  folder?: string
): Promise<Array<{ id: string; filename: string; folder: string; contentType: string; size: number; url: string; createdAt: string }>> {
  try {
    const db = await getMongoDb();
    const collection = db.collection<StoredTemplateImageDoc>("template_images");

    const query: any = { userId };
    if (folder && folder !== "all") {
      query.folder = folder;
    }

    const docs = await collection
      .find(query)
      .project({ _id: 1, userId: 1, folder: 1, filename: 1, contentType: 1, size: 1, url: 1, createdAt: 1 })
      .sort({ createdAt: -1 })
      .toArray();

    return docs.map((d) => ({
      id: d._id.toString(),
      filename: d.filename,
      folder: d.folder || "general",
      contentType: d.contentType,
      size: d.size,
      url: d.url || `/api/templates/images/${d._id.toString()}`,
      createdAt: d.createdAt,
    }));
  } catch (err: any) {
    console.warn("MongoDB getTemplateImages notice:", err.message);
    return [];
  }
}

/**
 * Retrieve single template image by ID from MongoDB
 */
export async function getTemplateImageByIdFromMongo(id: string): Promise<StoredTemplateImageDoc | null> {
  try {
    const db = await getMongoDb();
    const collection = db.collection<StoredTemplateImageDoc>("template_images");

    if (!ObjectId.isValid(id)) return null;
    return await collection.findOne({ _id: new ObjectId(id) });
  } catch (err: any) {
    console.error("MongoDB getTemplateImageById error:", err);
    return null;
  }
}

/**
 * Delete a template image by ID from MongoDB
 */
export async function deleteTemplateImageFromMongo(id: string, userId: string): Promise<boolean> {
  try {
    const db = await getMongoDb();
    const collection = db.collection<StoredTemplateImageDoc>("template_images");

    if (!ObjectId.isValid(id)) return false;
    const res = await collection.deleteOne({ _id: new ObjectId(id), userId });
    return res.deletedCount > 0;
  } catch (err: any) {
    console.error("MongoDB deleteTemplateImage error:", err);
    return false;
  }
}

export default clientPromise;
