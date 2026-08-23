
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
    const { file_id, otp } = await req.json()

    if (!file_id || !otp) {
      return new Response(JSON.stringify({ error: 'file_id and otp are required' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      })
    }

    // Initialize Supabase Admin Client using Service Role Key
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // 1. Fetch latest valid OTP record for file_id
    const { data: otpData, error: otpError } = await supabaseAdmin
      .from('file_otps')
      .select('*')
      .eq('file_id', file_id)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .single()

    if (otpError || !otpData) {
      return new Response(JSON.stringify({ error: 'OTP expired or not found. Please request a new one.' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      })
    }

    // 2. Check attempt limit (max 3 attempts)
    if (otpData.attempts >= 3) {
      return new Response(JSON.stringify({ error: 'Maximum OTP attempts reached. Please request a new one.' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 429,
      })
    }

    // 3. Hash provided OTP to compare
    const encoder = new TextEncoder()
    const data = encoder.encode(otp)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const providedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    if (providedHash !== otpData.otp_hash) {
      // Increment attempt counter
      await supabaseAdmin
        .from('file_otps')
        .update({ attempts: otpData.attempts + 1 })
        .eq('id', otpData.id)

      return new Response(JSON.stringify({ error: 'Invalid OTP' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 401,
      })
    }

    // 4. Valid OTP: Fetch key_share_b from encrypted_files
    const { data: fileData, error: fileError } = await supabaseAdmin
      .from('encrypted_files')
      .select('key_share_b')
      .eq('id', file_id)
      .single()

    if (fileError || !fileData) {
      return new Response(JSON.stringify({ error: 'Failed to retrieve KeyShare_B' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 500,
      })
    }

    // 5. Delete OTP record (One-Time Use)
    await supabaseAdmin
      .from('file_otps')
      .delete()
      .eq('id', otpData.id)

    // 6. Return key_share_b
    return new Response(JSON.stringify({ key_share_b: fileData.key_share_b }), {
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
