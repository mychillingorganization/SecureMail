// Paste this into browser console at http://localhost:5174/scanner
// to test the fetch directly and see detailed error info

(async () => {
  console.log("🧪 Starting fetch test...");
  
  try {
    // Read the test file from server
    const emlResponse = await fetch('/test7.eml');
    if (!emlResponse.ok) {
      throw new Error(`Failed to load test7.eml: ${emlResponse.status}`);
    }
    const emlBlob = await emlResponse.blob();
    console.log("✅ Loaded test7.eml from server:", emlBlob.size, "bytes");
    
    // Create FormData
    const formData = new FormData();
    formData.append("file", emlBlob, "test7.eml");
    formData.append("user_accepts_danger", "false");
    
    console.log("📤 Sending fetch request to http://localhost:8080/api/v1/scan-upload");
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      console.log("⏰ Timeout triggered - aborting request");
      controller.abort();
    }, 300000); // 5 minutes
    
    console.log("⏱️  Timeout set to 300000ms (5 minutes)");
    
    const startTime = Date.now();
    const response = await fetch("http://localhost:8080/api/v1/scan-upload", {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    const elapsedMs = Date.now() - startTime;
    
    console.log(`✅ Fetch completed in ${elapsedMs}ms`);
    console.log("📊 Response status:", response.status);
    console.log("📊 Response statusText:", response.statusText);
    console.log("📊 Response headers:");
    response.headers.forEach((value, key) => {
      console.log(`   ${key}: ${value}`);
    });
    
    if (!response.ok) {
      const text = await response.text();
      console.error("❌ Response not OK. Body:", text);
      throw new Error(`Server returned ${response.status}: ${text}`);
    }
    
    const data = await response.json();
    console.log("✅ SUCCESS! Response data:", data);
    
  } catch (error) {
    console.error("❌ Test failed:", error);
    if (error instanceof Error) {
      console.error("   Error name:", error.name);
      console.error("   Error message:", error.message);
      console.error("   Error stack:", error.stack);
    }
  }
})();
