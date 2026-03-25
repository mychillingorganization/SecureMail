// Browser Test Script - Test FormData Upload
// Open http://localhost:5174/scanner in browser
// Press F12, go to Console, and paste this entire script

(async () => {
  console.log("🧪 Testing Browser FormData Upload\n");
  
  const API_BASE_URL = "http://localhost:8080";
  
  // Step 1: Test simple GET to verify network works
  console.log("1️⃣  Testing basic connectivity...");
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();
    console.log("✅ Basic connectivity OK:", data);
  } catch (error) {
    console.error("❌ Basic connectivity failed:", error);
    return;
  }
  
  // Step 2: Test test-upload endpoint with FormData
  console.log("\n2️⃣  Testing test-upload endpoint with FormData...");
  try {
    // Create a test file (small one first)
    const testContent = "Test email content\n".repeat(100); // ~2KB
    const testFile = new File([testContent], "test.eml", { type: "application/octet-stream" });
    
    const formData = new FormData();
    formData.append("file", testFile);
    
    console.log("  Sending FormData with test file (size:", testFile.size, "bytes)...");
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 sec timeout
    
    const startTime = Date.now();
    const response = await fetch(`${API_BASE_URL}/api/v1/test-upload`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    
    const elapsed = Date.now() - startTime;
    console.log(`  Response received in ${elapsed}ms - Status: ${response.status}`);
    
    if (!response.ok) {
      const text = await response.text();
      console.error(`  ❌ Server returned ${response.status}: ${text}`);
      return;
    }
    
    const result = await response.json();
    console.log("✅ test-upload endpoint works!", result);
    
  } catch (error) {
    console.error("❌ test-upload failed:", error);
    if (error instanceof Error) {
      console.error("  Name:", error.name);
      console.error("  Message:", error.message);
    }
    return;
  }
  
  // Step 3: Now test with the actual scan-upload endpoint (but with a small file)
  console.log("\n3️⃣  Testing scan-upload endpoint...");
  try {
    const smallEml = "From: test@example.com\nTo: recipient@example.com\nSubject: Test\n\nTest body".repeat(10);
    const emlFile = new File([smallEml], "test.eml", { type: "application/octet-stream" });
    
    const formData = new FormData();
    formData.append("file", emlFile);
    formData.append("user_accepts_danger", "false");
    
    console.log("  Sending to scan-upload endpoint...");
    
    //  60 second timeout for this
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);
    
    const startTime = Date.now();
    const response = await fetch(`${API_BASE_URL}/api/v1/scan-upload`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    
    const elapsed = Date.now() - startTime;
    console.log(`  Response in ${elapsed}ms - Status: ${response.status}`);
    
    if (!response.ok) {
      const text = await response.text();
      console.error(`  ❌ Server returned ${response.status}: ${text.substring(0, 200)}`);
      return;
    }
    
    const result = await response.json();
    console.log("✅ scan-upload endpoint works!", result);
    
  } catch (error) {
    console.error("❌ scan-upload failed:", error);
    if (error instanceof Error) {
      console.error("  Name:", error.name);
      console.error("  Message:", error.message);
    }
  }
  
  console.log("\n✅ All tests completed! The network connection is working.");
  console.log("📝 If you're still seeing errors in the actual EmailScanner component:");
  console.log("   - Check the browser DevTools Network tab for the actual request/response");
  console.log("   - Look for CORS errors in the console");
  console.log("   - Try selecting test7.eml and clicking Scan Email again");
  
})();
