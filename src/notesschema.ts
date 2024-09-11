import mongoose, { Schema, Document } from "mongoose";

export interface INote extends Document {
  title: string;
  content: string;
  tags: string[]; // Array of tags to support multiple filters
  createdAt: Date;
  updatedAt: Date;
  owner: string;
}

const NoteSchema: Schema = new Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  tags: {
    type: [String],
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  owner: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
});

// Update `updatedAt` field before saving
NoteSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

export const Note: any = mongoose.model<INote>("Note", NoteSchema);
