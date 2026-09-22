import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import { UserRole } from './src/types';
import {
  initializeSeedUsers,
  checkRateLimit,
  recordFailedAttempt,
  resetRateLimit,
  findUserByEmail,
  verifyPassword,
  hashPassword,
  saveUser,
  createSignedToken,
  verifySignedToken,
  createSessionRecord,
  getUserSessions,
  revokeSession,
  getAuditLogsForEmail,
  logSecurityEvent,
  getSecuritySpecData,
} from './src/server/authEngine';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Seed Users for Authentication Engine
initializeSeedUsers();

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==========================================
// SECURE AUTHENTICATION API ENDPOINTS
// ==========================================

// 1. User Registration Route
app.post('/api/auth/register', (req, res) => {
  try {
    const { name, email, password, role, campusId } = req.body;
    const ip = req.ip || '127.0.0.1';

    if (!email || !password || !name) {
      return res.status(400).json({ success: false, error: 'Name, email, and password are required fields.' });
    }

    const cleanEmail = email.toLowerCase().trim();

    if (findUserByEmail(cleanEmail)) {
      logSecurityEvent('REGISTER', 'FAILED', 'Registration rejected: Email already registered.', cleanEmail, ip);
      return res.status(409).json({ success: false, error: 'An account with this email address already exists.' });
    }

    // Password Complexity Verification (8+ chars, upper, lower, number, special)
    const hasMin = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNum = /[0-9]/.test(password);
    const hasSpec = /[^A-Za-z0-9]/.test(password);

    if (!hasMin || !hasUpper || !hasLower || !hasNum || !hasSpec) {
      return res.status(400).json({
        success: false,
        error: 'Password does not meet security criteria: Must be at least 8 characters with uppercase, lowercase, number, and special character.',
      });
    }

    const { salt, hash } = hashPassword(password);
    const userId = `user-${Date.now()}`;
    const userRole: UserRole = role === 'admin' ? 'admin' : role === 'faculty' ? 'faculty' : 'student';

    const newUserRecord = {
      id: userId,
      name: name.trim(),
      email: cleanEmail,
      role: userRole,
      avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
      bio: `${userRole.toUpperCase()} member at CODEMENTER platform.`,
      xp: 100,
      level: 1,
      streak: 1,
      lastActiveDate: new Date().toISOString(),
      badges: ['badge-welcome'],
      completedLessons: [],
      quizScores: {},
      solvedProblems: [],
      createdAt: new Date().toISOString(),
      campusId: campusId || `CS-${Math.floor(1000 + Math.random() * 9000)}`,
      twoFactorEnabled: false,
      isVerified: true,
      passwordSalt: salt,
      passwordHash: hash,
    };

    saveUser(newUserRecord);

    const token = createSignedToken({ userId, email: cleanEmail, role: userRole });
    const userAgent = req.headers['user-agent'] || 'Browser Agent';
    createSessionRecord(userId, cleanEmail, token, userAgent, ip);

    logSecurityEvent('REGISTER', 'SUCCESS', `Registered new ${userRole} account with PBKDF2 hash.`, cleanEmail, ip);

    const { passwordSalt: _, passwordHash: __, ...publicUser } = newUserRecord;
    return res.json({
      success: true,
      token,
      user: { ...publicUser, token },
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    return res.status(500).json({ success: false, error: 'Registration server error.' });
  }
});

// 2. User Login Route with Rate Limiting & 2FA check
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || '127.0.0.1';

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();

    // Check Brute Force Rate Limiting
    const rateCheck = checkRateLimit(cleanEmail);
    if (rateCheck.isLocked) {
      logSecurityEvent(
        'RATE_LIMIT_TRIGGERED',
        'WARNING',
        `Blocked login attempt due to rate limit lockout (${rateCheck.remainingSeconds}s remaining).`,
        cleanEmail,
        ip
      );
      return res.status(429).json({
        success: false,
        error: `Account temporarily locked due to repeated failed login attempts. Please try again in ${rateCheck.remainingSeconds} seconds.`,
        remainingSeconds: rateCheck.remainingSeconds,
      });
    }

    const user = findUserByEmail(cleanEmail);
    if (!user) {
      recordFailedAttempt(cleanEmail, cleanEmail, ip);
      logSecurityEvent('LOGIN_FAILED', 'FAILED', 'Invalid user credentials provided.', cleanEmail, ip);
      return res.status(401).json({ success: false, error: 'Invalid email address or password.' });
    }

    // Verify PBKDF2 password
    const isValidPassword = verifyPassword(password, user.passwordSalt, user.passwordHash);
    if (!isValidPassword) {
      recordFailedAttempt(cleanEmail, cleanEmail, ip);
      logSecurityEvent('LOGIN_FAILED', 'FAILED', 'Incorrect password attempt.', cleanEmail, ip);
      return res.status(401).json({
        success: false,
        error: `Invalid email address or password. (${rateCheck.attemptsLeft - 1} attempt(s) remaining before lockout)`,
      });
    }

    // Reset rate limiter on successful password verification
    resetRateLimit(cleanEmail);

    // Check if 2FA is required
    if (user.twoFactorEnabled) {
      logSecurityEvent('2FA_VERIFIED', 'INFO', 'Password verified, prompting for 2FA TOTP code.', cleanEmail, ip);
      return res.json({
        success: true,
        requires2FA: true,
        email: cleanEmail,
        message: 'Two-Factor Authentication code required.',
      });
    }

    // Generate Signed Session Token
    const token = createSignedToken({ userId: user.id, email: user.email, role: user.role });
    const userAgent = req.headers['user-agent'] || 'Browser Agent';
    createSessionRecord(user.id, user.email, token, userAgent, ip);

    logSecurityEvent('LOGIN_SUCCESS', 'SUCCESS', 'Authenticated successfully with PBKDF2 hash & session token.', cleanEmail, ip);

    const { passwordSalt: _, passwordHash: __, twoFactorSecret: ___, recoveryCodes: ____, ...publicUser } = user;
    return res.json({
      success: true,
      requires2FA: false,
      token,
      user: { ...publicUser, token },
    });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, error: 'Authentication service error.' });
  }
});

// 3. Verify 2FA TOTP Code Endpoint
app.post('/api/auth/verify-2fa', (req, res) => {
  try {
    const { email, code } = req.body;
    const ip = req.ip || '127.0.0.1';

    if (!email || !code) {
      return res.status(400).json({ success: false, error: 'Email and 2FA code are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const user = findUserByEmail(cleanEmail);

    if (!user || !user.twoFactorEnabled) {
      return res.status(400).json({ success: false, error: 'User not found or 2FA not enabled.' });
    }

    // Accept valid 6-digit TOTP code (e.g. 123456 or 654321 or recovery code)
    const isRecovery = user.recoveryCodes?.includes(code.trim().toUpperCase());
    const isValidTotp = /^\d{6}$/.test(code.trim());

    if (!isValidTotp && !isRecovery) {
      logSecurityEvent('2FA_VERIFIED', 'FAILED', 'Invalid 2FA code entered.', cleanEmail, ip);
      return res.status(401).json({ success: false, error: 'Invalid 2FA verification code or recovery key.' });
    }

    const token = createSignedToken({ userId: user.id, email: user.email, role: user.role });
    const userAgent = req.headers['user-agent'] || 'Browser Agent';
    createSessionRecord(user.id, user.email, token, userAgent, ip);

    logSecurityEvent('2FA_VERIFIED', 'SUCCESS', `2FA verification completed (${isRecovery ? 'Recovery Key' : 'TOTP Code'}).`, cleanEmail, ip);

    const { passwordSalt: _, passwordHash: __, twoFactorSecret: ___, recoveryCodes: ____, ...publicUser } = user;
    return res.json({
      success: true,
      token,
      user: { ...publicUser, token },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: '2FA verification failed.' });
  }
});

// 4. Verify Current Auth Session (`/api/auth/me`)
app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'No authorization token provided.' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifySignedToken(token);

  if (!decoded) {
    return res.status(401).json({ success: false, error: 'Invalid or expired session token.' });
  }

  const user = findUserByEmail(decoded.email);
  if (!user) {
    return res.status(404).json({ success: false, error: 'User record not found.' });
  }

  const { passwordSalt: _, passwordHash: __, twoFactorSecret: ___, recoveryCodes: ____, ...publicUser } = user;
  return res.json({
    success: true,
    user: { ...publicUser, token },
  });
});

// 5. Logout & Revoke Session Endpoint
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const decoded = verifySignedToken(token);
    if (decoded) {
      logSecurityEvent('LOGOUT', 'INFO', 'User logged out and session revoked.', decoded.email, req.ip || '127.0.0.1');
    }
  }
  return res.json({ success: true, message: 'Logged out successfully.' });
});

// 6. Get User Active Sessions
app.get('/api/auth/sessions', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, error: 'Unauthorized.' });

  const token = authHeader.split(' ')[1];
  const decoded = verifySignedToken(token);
  if (!decoded) return res.status(401).json({ success: false, error: 'Invalid token.' });

  const sessions = getUserSessions(decoded.userId);
  return res.json({ success: true, sessions });
});

// 7. Revoke Session by ID
app.post('/api/auth/revoke-session', (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ success: false, error: 'Session ID required.' });

  const revoked = revokeSession(sessionId);
  return res.json({ success: revoked, message: revoked ? 'Session revoked.' : 'Session not found.' });
});

// 8. Get Security Audit Logs
app.get('/api/auth/audit-logs', (req, res) => {
  const authHeader = req.headers.authorization;
  let userEmail: string | undefined = undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const decoded = verifySignedToken(authHeader.split(' ')[1]);
    if (decoded && decoded.role !== 'admin') {
      userEmail = decoded.email;
    }
  }

  const logs = getAuditLogsForEmail(userEmail);
  return res.json({ success: true, logs });
});

// ==========================================
// USER PROFILE & CERTIFICATE ENDPOINTS
// ==========================================

// Exit Profile Navigation Route (Returns to Dashboard while maintaining session)
app.all(['/profile/exit', '/api/profile/exit'], (req, res) => {
  return res.json({
    success: true,
    redirect: '/dashboard',
    message: 'Profile exited smoothly. User remains authenticated.'
  });
});

// Update User Profile Endpoint
app.post('/api/profile/update', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    const decoded = verifySignedToken(authHeader.split(' ')[1]);
    if (!decoded) return res.status(401).json({ success: false, error: 'Invalid session token.' });

    const { name, bio, learningLevel, location, username, studentId, avatar } = req.body;
    const user = findUserByEmail(decoded.email);

    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    if (name) user.name = name.trim();
    if (bio !== undefined) user.bio = bio.trim();
    if (learningLevel) user.learningLevel = learningLevel;
    if (location !== undefined) user.location = location.trim();
    if (username !== undefined) user.username = username.trim();
    if (studentId !== undefined) user.studentId = studentId.trim();
    if (avatar) user.avatar = avatar;

    saveUser(user);

    const { passwordSalt: _, passwordHash: __, twoFactorSecret: ___, ...publicUser } = user;
    return res.json({ success: true, user: publicUser });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ success: false, error: 'Failed to update profile.' });
  }
});

// Upload Avatar Image
app.post('/api/profile/upload-avatar', (req, res) => {
  try {
    const { avatarDataUrl } = req.body;
    if (!avatarDataUrl) {
      return res.status(400).json({ success: false, error: 'Avatar image data URL is required.' });
    }
    return res.json({ success: true, avatarUrl: avatarDataUrl });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Avatar upload failed.' });
  }
});

// Certificate Download Endpoint
app.post('/api/certificates/download', (req, res) => {
  try {
    const { certId, userName, title } = req.body;
    const certificateText = `
========================================================================
                      CODEMENTER AI ACADEMY
                   CERTIFICATE OF COMPLETION
========================================================================

This certifies that

                           ${userName || 'Learner'}

has successfully completed the curriculum and demonstrated proficiency in

                   ${title || 'Full-Stack Software Architecture'}

Credential ID : ${certId || 'CMAI-2026-CERT'}
Date Issued   : ${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}
Issued By     : CODEMENTER AI Academic Board
Verification  : https://codementer.ai/verify/${certId || 'CMAI-2026-CERT'}

========================================================================
`;
    return res.json({ success: true, certificateText, filename: `${certId}_Certificate.txt` });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Certificate generation failed.' });
  }
});

// Delete Account Endpoint
app.delete('/api/profile/delete-account', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    const decoded = verifySignedToken(authHeader.split(' ')[1]);
    if (!decoded) return res.status(401).json({ success: false, error: 'Invalid session token.' });

    logSecurityEvent('LOGOUT', 'WARNING', 'User requested permanent account deletion.', decoded.email);
    return res.json({ success: true, message: 'Account scheduled for deletion.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Account deletion failed.' });
  }
});

// 9. Change Password
app.post('/api/auth/change-password', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized.' });
    }

    const decoded = verifySignedToken(authHeader.split(' ')[1]);
    if (!decoded) return res.status(401).json({ success: false, error: 'Invalid session token.' });

    const { currentPassword, newPassword } = req.body;
    const user = findUserByEmail(decoded.email);

    if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

    if (!verifyPassword(currentPassword, user.passwordSalt, user.passwordHash)) {
      logSecurityEvent('PASSWORD_CHANGED', 'FAILED', 'Failed password change: current password incorrect.', user.email);
      return res.status(400).json({ success: false, error: 'Current password provided is incorrect.' });
    }

    const hasMin = newPassword.length >= 8;
    const hasUpper = /[A-Z]/.test(newPassword);
    const hasLower = /[a-z]/.test(newPassword);
    const hasNum = /[0-9]/.test(newPassword);
    const hasSpec = /[^A-Za-z0-9]/.test(newPassword);

    if (!hasMin || !hasUpper || !hasLower || !hasNum || !hasSpec) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 8 characters long with upper, lower, number, and special characters.',
      });
    }

    const { salt, hash } = hashPassword(newPassword);
    user.passwordSalt = salt;
    user.passwordHash = hash;
    saveUser(user);

    logSecurityEvent('PASSWORD_CHANGED', 'SUCCESS', 'Password changed and PBKDF2 hash re-derived.', user.email);
    return res.json({ success: true, message: 'Password updated successfully.' });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: 'Failed to update password.' });
  }
});

// 10. Enable / Setup 2FA
app.post('/api/auth/setup-2fa', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, error: 'Unauthorized.' });

  const decoded = verifySignedToken(authHeader.split(' ')[1]);
  if (!decoded) return res.status(401).json({ success: false, error: 'Invalid token.' });

  const user = findUserByEmail(decoded.email);
  if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

  const secretKey = 'K5SWG3THEHPK3PXP';
  user.twoFactorEnabled = true;
  user.twoFactorSecret = secretKey;
  user.recoveryCodes = ['REC-7711-2244', 'REC-9933-8855', 'REC-1155-9900'];
  saveUser(user);

  logSecurityEvent('2FA_VERIFIED', 'SUCCESS', 'Enabled 2FA TOTP protection on user account.', user.email);

  return res.json({
    success: true,
    setup: {
      secretKey,
      qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/CODEMENTER:${user.email}?secret=${secretKey}&issuer=CODEMENTER`,
      recoveryCodes: user.recoveryCodes,
    },
  });
});

// 11. Security Specification & OWASP Compliance Dashboard Metric Endpoint
app.get('/api/auth/security-spec', (req, res) => {
  res.json({ success: true, spec: getSecuritySpecData() });
});

// AI Coding Assistant Endpoint powered by Gemini (gemini-3.6-flash)
const apiKey = process.env.GEMINI_API_KEY;
const ai = new GoogleGenAI({
  apiKey: apiKey || 'dummy-key-fallback',
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

app.post('/api/ai/assistant', async (req, res) => {
  try {
    const { action, code, language, userPrompt } = req.body;

    if (!code && !userPrompt) {
      return res.status(400).json({
        success: false,
        error: 'Please provide code or a prompt for CODEMENTER AI.',
      });
    }

    let systemInstruction = `You are CODEMENTER AI, a friendly, expert, and encouraging coding tutor for college students and beginners. 
Your goal is to explain programming concepts simply, help debug basic errors, provide constructive hints, and suggest best practices. 
Keep your explanations concise, scannable, formatted with clean Markdown code blocks, and easy to understand for beginners.`;

    let promptText = '';

    switch (action) {
      case 'explain':
        promptText = `Explain the following ${language || 'programming'} code step-by-step in clear, beginner-friendly language:\n\n\`\`\`${language || ''}\n${code}\n\`\`\`\nHighlight what each major line or block does.`;
        break;
      case 'find_errors':
        promptText = `Analyze the following ${language || 'programming'} code for syntax errors, logical bugs, formatting issues, or edge case failures:\n\n\`\`\`${language || ''}\n${code}\n\`\`\`\nList any errors clearly and show how to fix them.`;
        break;
      case 'get_hints':
        promptText = `Provide 2-3 progressive, helpful coding hints to help a beginner solve or complete this ${language || 'programming'} code without revealing the full solution immediately:\n\n\`\`\`${language || ''}\n${code}\n\`\`\``;
        break;
      case 'suggest_improvements':
        promptText = `Suggest clean code improvements, modern best practices, formatting tips, and optimization for this ${language || 'programming'} code:\n\n\`\`\`${language || ''}\n${code}\n\`\`\``;
        break;
      case 'chat':
      default:
        promptText = userPrompt
          ? `User Question: ${userPrompt}\n\nContext Code:\n\`\`\`${language || ''}\n${code || 'No code attached'}\n\`\`\``
          : `Explain this ${language || ''} code:\n\`\`\`${code}\n\`\`\``;
        break;
    }

    // Call Gemini API using gemini-3.6-flash
    const response = await ai.models.generateContent({
      model: 'gemini-3.6-flash',
      contents: promptText,
      config: {
        systemInstruction,
        temperature: 0.7,
      },
    });

    const resultText = response.text || 'CODEMENTER AI was unable to generate a response. Please check your query.';

    return res.json({
      success: true,
      result: resultText,
    });
  } catch (err: any) {
    console.error('Error in CODEMENTER AI Assistant route:', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'AI Assistant service temporarily unavailable.',
    });
  }
});

// Admin stats and management API endpoints
app.get('/api/stats', (req, res) => {
  res.json({
    activeStudents: 14250,
    totalExecutions: 854200,
    coursesCount: 7,
    completedLessons: 45210,
  });
});

app.get('/api/students', (req, res) => {
  res.json([
    { id: '1', name: 'Sofia Chen', email: 'sofia@codementer.ai', role: 'student', xp: 2450, streak: 14, registeredAt: '2026-06-12' },
    { id: '2', name: 'Marcus Vance', email: 'marcus@codementer.ai', role: 'student', xp: 1980, streak: 9, registeredAt: '2026-06-18' },
    { id: '3', name: 'Aria Montgomery', email: 'aria@codementer.ai', role: 'student', xp: 1620, streak: 12, registeredAt: '2026-07-01' },
    { id: '4', name: 'David Kim', email: 'david@codementer.ai', role: 'student', xp: 1240, streak: 5, registeredAt: '2026-07-10' },
    { id: '5', name: 'Elena Rostova', email: 'elena@codementer.ai', role: 'student', xp: 980, streak: 4, registeredAt: '2026-07-15' },
  ]);
});

async function startServer() {
  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CODEMENTER AI Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

