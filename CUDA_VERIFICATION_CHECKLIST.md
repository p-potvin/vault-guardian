# CUDA Integration - Verification Checklist

## Pre-Launch Verification

Run these checks before launching the application:

### ✅ Build Verification
- [ ] Run `dotnet build` - should complete successfully
- [ ] No compilation errors
- [ ] No warnings (if possible)
- [ ] Output shows: "Build successful"

### ✅ Binary Verification
- [ ] Check `libs/cuda/bin/x64/` contains 4 DLLs:
  ```
  cudart64_12.dll
  cupti64_120.dll
  cupti64_118.dll
  nvml.dll
  ```
- [ ] Each file is non-zero size (not corrupted)
- [ ] Files are readable

### ✅ Output Directory Verification
- [ ] Check `src/VaultGuardian.Core/bin/x64/Debug/net10.0/bin/x64/` contains same 4 DLLs
- [ ] Files copied successfully during build

### ✅ Test Verification
- [ ] Run `dotnet test --filter "CudaProfilerTests"`
- [ ] All 7 tests pass
- [ ] Test output shows: "7 Tests (7 Passed, 0 Failed, 0 Skipped)"

### ✅ Project File Verification
- [ ] `VaultGuardian.Core.csproj` contains binary copy rule
- [ ] Rule has `CopyToOutputDirectory="PreserveNewest"`

## Launch Verification

### ✅ Application Startup
1. Launch `VaultGuardian.UI.exe` or use `dotnet run`
2. Application should start without crashing
3. Exit code should NOT be `0xc0000602` or similar

### ✅ Debug Output Check
1. Open Visual Studio > Debug > Windows > Output
2. Look for one of these messages:
   - ✅ "CUPTI GPU profiler initialized successfully" → CUDA working
   - ✅ "NVML not initialized; GPU profiling unavailable." → CUDA unavailable (expected)
   - ✅ "CUDA library loader initialization failed:" → CUDA unavailable (expected)

3. Should NOT see:
   - ❌ "DllNotFoundException"
   - ❌ "Unable to load DLL"
   - ❌ Unhandled exceptions

### ✅ Runtime Behavior
1. Run the application for 10+ seconds
2. No crashes
3. No memory leaks (check Task Manager)
4. UI responsive

## Functional Verification

### ✅ Core Functionality
- [ ] Application main window displays
- [ ] UI is responsive
- [ ] No freeze/hangs on startup
- [ ] Can interact with controls

### ✅ GPU Monitoring (if CUDA available)
- [ ] Check ResourceMonitor or monitoring UI
- [ ] GPU metrics displayed (or N/A if no GPU)
- [ ] No errors in metrics

### ✅ Multiple Instances
- [ ] Can create multiple CudaProfiler instances
- [ ] No conflicts or crashes
- [ ] All instances dispose cleanly

## Troubleshooting Decision Tree

### Application Crashes on Startup (Exit Code 0xc0000602)
```
├─ Check libs/cuda/bin/x64/ has 4 DLLs
│  ├─ Missing? → Run setup script
│  └─ Corrupt? → Delete and re-copy
├─ Check Visual Studio Output for messages
│  ├─ "CUDA library loader initialization failed"
│  │  └─ Try: Disable CUDA profiler temporarily
│  ├─ No messages? → Enable more verbose logging
│  └─ Memory corruption? → Clean rebuild
└─ Last resort: Comment out CudaProfiler in App.xaml.cs
```

### Application Runs but GPU Monitoring Not Working
```
├─ Expected behavior if CUDA unavailable
├─ Check Visual Studio Output:
│  ├─ "NVML not initialized" → Normal
│  ├─ "CUPTI initialization failed" → Normal
│  └─ Error message? → Read it carefully
└─ Re-run setup-cuda-binaries.ps1 to fix
```

### Application Runs but Lots of Debug Messages
```
├─ Expected if CUDA diagnostics enabled
├─ Normal messages:
│  ├─ "CUDA library loader initialization failed"
│  ├─ "NVML initialization failed"
│  └─ "GPU profiling unavailable"
└─ These are OK - graceful degradation working
```

### Build Fails with File Not Found
```
├─ Error mentions .dll file?
├─ Check: File exists in libs/cuda/bin/x64/
└─ If missing → Run setup-cuda-binaries.ps1
```

## Performance Verification

### ✅ Startup Time
- [ ] First startup: <5 seconds
- [ ] Subsequent startups: <2 seconds
- [ ] No noticeable delay from CUDA loading

### ✅ Memory Usage
- [ ] Check Task Manager before launch
- [ ] Launch application
- [ ] Memory increase ~50-100 MB (normal)
- [ ] No continuous memory growth (memory leak)

### ✅ CPU Usage
- [ ] After startup, CPU usage normal
- [ ] No 100% CPU usage
- [ ] Responsive to user input

## Success Criteria

Your CUDA integration is successful when:

✅ **Build Phase**
- Project builds without errors
- Binaries copied to output directory
- Tests pass (7/7)

✅ **Startup Phase**
- Application starts without crash
- No `0xc0000602` exit code
- No unhandled exceptions

✅ **Runtime Phase**
- Application is responsive
- GPU monitoring available or gracefully disabled
- Debug output shows status messages
- No memory leaks

✅ **Shutdown Phase**
- Application closes cleanly
- No crash on exit
- All resources released

## Final Checklist

Before declaring success, verify ALL of these:

- [ ] `dotnet build` passes
- [ ] `dotnet test` shows 7/7 passed
- [ ] Application launches without crash
- [ ] UI appears and is responsive
- [ ] Output window shows CUDA status message
- [ ] No error messages in Output window
- [ ] Can use application normally for >1 minute
- [ ] Application closes cleanly
- [ ] No memory leaks (Task Manager)

## Sign-Off

Once all checks are complete and passing:

```
✅ CUDA Integration Verified
✅ Application Stable
✅ Ready for Production
```

Date: ______________
Environment: Windows x64
.NET Version: 10.0
CUDA Status: [ENABLED / DISABLED]
Issues Found: [NONE / list any]

---

**Next Steps**:
- Run through verification checklist
- Report any failures to troubleshooting guide
- Deploy to production once all checks pass
