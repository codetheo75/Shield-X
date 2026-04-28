import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware to parse query params
  app.use(express.json());

  // API Route to fetch target URL
  app.get("/api/fetch", async (req, res) => {
    try {
      const targetUrl = req.query.url as string;
      if (!targetUrl) {
        return res.status(400).json({ error: "Missing 'url' query parameter" });
      }

      // Basic validation
      new URL(targetUrl);

      // Fetch the content
      const response = await fetch(targetUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        },
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: `Failed to fetch: ${response.statusText}`, summary: `HTTP ${response.status}` });
      }

      const contentType = response.headers.get("content-type") || "";
      let content = "";
      
      if (contentType.includes("text/html") || contentType.includes("text/plain")) {
        content = await response.text();
      } else {
        return res.status(400).json({ error: "Only HTML or Text content is supported for scanning." });
      }

      res.json({ targetUrl, contentType, content });
    } catch (error: any) {
      console.error("Error fetching URL:", error);
      res.status(500).json({ error: error.message || "Failed to fetch the URL content" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Standard setup for serving static files in production
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
