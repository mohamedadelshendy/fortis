
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { file_id, email } = await req.json()

    if (!file_id || !email) {
      return new Response(JSON.stringify({ error: 'file_id and email are required' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      })
    }

    // Initialize Supabase Admin Client using Service Role Key to bypass RLS
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // 1. Verify file_id and email match an existing record
    const { data: fileData, error: fileError } = await supabaseAdmin
      .from('encrypted_files')
      .select('id, user_email')
      .eq('id', file_id)
      .single()

    if (fileError || !fileData) {
      return new Response(JSON.stringify({ error: 'File not found' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 404,
      })
    }

    if (fileData.user_email !== email) {
      return new Response(JSON.stringify({ error: 'Unauthorized email for this file' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 403,
      })
    }

    // 2. Generate 6-digit cryptographically secure OTP
    const array = new Uint32Array(1)
    crypto.getRandomValues(array)
    // Map to 100000 - 999999
    const otp = (array[0] % 900000) + 100000
    const otpString = otp.toString()

    // 3. Hash OTP with SHA-256 for secure storage
    const encoder = new TextEncoder()
    const data = encoder.encode(otpString)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const otpHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    // 4. Set expiration time (10 minutes from now)
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString()

    // 5. Insert hash into file_otps table
    const { error: insertError } = await supabaseAdmin
      .from('file_otps')
      .insert({
        file_id: file_id,
        otp_hash: otpHash,
        expires_at: expiresAt,
        attempts: 0
      })

    if (insertError) {
      throw insertError
    }

    // 6. Send email via Resend API
    const resendApiKey = Deno.env.get('RESEND_API_KEY')
    if (!resendApiKey) {
      throw new Error('RESEND_API_KEY is not set')
    }

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${resendApiKey}`
      },
      body: JSON.stringify({
        from: 'onboarding@resend.dev', // Resend default testing domain (only sends to your registered email)
        to: email,
        subject: 'Your Decryption OTP',
        html: `<p>Your One-Time Password for file decryption is: <strong>${otpString}</strong></p><p>This code will expire in 10 minutes.</p>`
      })
    })

    if (!resendRes.ok) {
      const resendError = await resendRes.text()
      console.error('Resend error:', resendError)
      throw new Error('Failed to send email via Resend')
    }

    return new Response(JSON.stringify({ message: 'OTP sent successfully' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 200,
    })

  } catch (error) {
    console.error('Error processing request:', error)
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 500,
    })
  }
})
