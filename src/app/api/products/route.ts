import clientPromise from "@lib/mongodb";
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const client = await clientPromise;
    const db = client.db("gumroad");
    const products = await db.collection("products").find({}).sort({ createdAt: -1 }).toArray();
    return NextResponse.json({ products })
  } catch (error) {
    console.error("Error fetching data from MongoDB:", error);
    return NextResponse.json({ error: "..." }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const client = await clientPromise;
    const db = client.db("gumroad");
    const bodyObject = await req.json();
    await db.collection("products").insertOne(bodyObject);
      // console.log(body);
      return NextResponse.json({
        status: 200,
        data: bodyObject
      })
  } catch (error) {
    console.error("Error fetching data from MongoDB:", error);
    return NextResponse.json({ error: "..." }, { status: 500 });
  }
}