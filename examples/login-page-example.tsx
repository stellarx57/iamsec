/**
 * IAMsec - Example: Login Page Component
 * File: src/app/auth/login/page.tsx
 */

'use client';

import React, { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  Box,
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  FormControlLabel,
  Checkbox,
  Link as MuiLink,
  CircularProgress,
} from '@mui/material';
import Link from 'next/link';
import { useAuth } from '@/iamsec';

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectUrl = searchParams.get('redirect') || '/account';
  
  const { login, isLoading } = useAuth();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const result = await login({
        email,
        password,
        rememberMe,
      });

      if (result.success) {
        // Redirect to original destination or account page
        router.push(redirectUrl);
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err) {
      setError('An unexpected error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          py: 4,
        }}
      >
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom textAlign="center">
            Sign In
          </Typography>

          <Typography variant="body2" color="text.secondary" textAlign="center" mb={3}>
            Enter your credentials to access your account
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit} noValidate>
            <TextField
              fullWidth
              label="Email Address"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              autoFocus
              margin="normal"
              disabled={isSubmitting}
            />

            <TextField
              fullWidth
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              margin="normal"
              disabled={isSubmitting}
            />

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2 }}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    disabled={isSubmitting}
                  />
                }
                label="Remember me"
              />

              <MuiLink component={Link} href="/auth/forgot-password" variant="body2">
                Forgot password?
              </MuiLink>
            </Box>

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={isSubmitting || !email || !password}
              sx={{ mt: 3, mb: 2 }}
            >
              {isSubmitting ? (
                <>
                  <CircularProgress size={20} sx={{ mr: 1 }} />
                  Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </Button>

            <Typography variant="body2" textAlign="center" mt={2}>
              Don't have an account?{' '}
              <MuiLink component={Link} href="/auth/register">
                Sign up
              </MuiLink>
            </Typography>
          </Box>
        </Paper>

        <Typography variant="caption" color="text.secondary" textAlign="center" mt={4}>
          Protected by IAMsec - Enterprise-grade security
        </Typography>
      </Box>
    </Container>
  );
}

