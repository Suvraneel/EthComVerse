import clientPromise from "@lib/mongodb";
import { ObjectId } from "mongodb";
import { NextResponse } from 'next/server';

export async function GET(req: Request) {
    try {
      const client = await clientPromise;
      const db = client.db("gumroad");
      const { searchParams } = new URL(req.url)
      const id = searchParams.get('id')
      const query = { _id: new ObjectId(Array.isArray(id)?id[0]:id) };
      const product = await db.collection("products").findOne(query);
      return NextResponse.json({ product })
    } catch (error) {
      console.error("Error fetching data from MongoDB:", error);
      return NextResponse.json({ error: "..." }, { status: 500 });
    }
  }