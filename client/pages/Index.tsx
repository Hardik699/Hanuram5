import { DemoResponse } from "@shared/api";
import { useEffect, useState } from "react";

export default function Index() {
  const [exampleFromServer, setExampleFromServer] = useState("");
  // Fetch users on component mount
  useEffect(() => {
    fetchDemo();
  }, []);

  // Example of how to fetch data from the server (if needed)
  const fetchDemo = async () => {
    try {
      const response = await fetch("/api/demo");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = (await response.json()) as DemoResponse;
      setExampleFromServer(data.message);
    } catch (error) {
      console.error("Error fetching hello:", error);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200">
      <div className="text-center">
        {/* DUDHI HALWA Heading */}
        <h1 className="mb-8 inline-block bg-blue-600 rounded-2xl px-8 py-6 drop-shadow-xl">
          <img
            src="https://cdn.builder.io/api/v1/image/assets%2F11df88887a504a0e84b722c1bfa40315%2F734e4f7a6db646eea0a6fb364420da6c?format=webp&width=800&height=1200"
            alt="DUDHI HALWA"
            className="h-20 w-auto"
          />
        </h1>
        <p className="mt-4 text-slate-600 max-w-md">
          Watch the chat on the left for updates that might need your attention
          to finish generating
        </p>
        <p className="mt-4 hidden max-w-md">{exampleFromServer}</p>
      </div>
    </div>
  );
}



