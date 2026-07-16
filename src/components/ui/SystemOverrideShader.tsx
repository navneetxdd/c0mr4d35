"use client";

import { useEffect, useRef } from "react";

const vertexShaderSource = `
  attribute vec2 position;
  void main() {
    gl_Position = vec4(position, 0.0, 1.0);
  }
`;

const fragmentShaderSource = `
  precision highp float;
  
  uniform vec2 u_resolution;
  uniform float u_time;
  uniform vec2 u_mouse;
  
  // Hash function for noise
  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453123);
  }

  // Neon Green Base (Datum's --live color: #b8f04c / RGB: 184, 240, 76)
  vec3 getLiveColor() {
    return vec3(184.0 / 255.0, 240.0 / 255.0, 76.0 / 255.0);
  }

  void main() {
    vec2 uv = gl_FragCoord.xy / u_resolution.xy;
    vec2 p = uv * 2.0 - 1.0;
    p.x *= u_resolution.x / u_resolution.y;
    
    // Normalized mouse position
    vec2 mouse = u_mouse / u_resolution.xy;
    mouse = mouse * 2.0 - 1.0;
    mouse.x *= u_resolution.x / u_resolution.y;

    // 1. Dynamic Grid (dual-layered)
    vec2 gridUV = uv * 20.0;
    vec2 gridUV2 = uv * 100.0;
    
    // Slight perspective/distortion for grid
    gridUV.y += sin(gridUV.x * 0.5 + u_time * 0.5) * 0.1;
    
    float grid1 = max(step(0.98, fract(gridUV.x)), step(0.98, fract(gridUV.y)));
    float grid2 = max(step(0.95, fract(gridUV2.x)), step(0.95, fract(gridUV2.y)));
    
    float gridAlpha = (grid1 * 0.3) + (grid2 * 0.08);

    // 2. Glitchy Scanlines
    float scanline = sin(uv.y * 800.0 + u_time * 10.0) * 0.04;
    float heavyScanline = sin(uv.y * 50.0 - u_time * 2.0) * 0.1;
    float scanAlpha = scanline + heavyScanline;

    // 3. Procedural Data Pulses (Horizontal sweeps)
    float pulse = smoothstep(0.98, 1.0, sin(uv.y * 5.0 - u_time * 1.5));
    pulse += smoothstep(0.99, 1.0, sin(uv.y * 15.0 + u_time * 3.0)) * 0.5;

    // 4. Interactive Glow (Cursor vignette)
    // Distance from current pixel to mouse
    float distToMouse = length(p - mouse);
    float glow = 1.0 - smoothstep(0.0, 1.2, distToMouse);
    // Add a pulsing effect to the glow
    glow *= 0.8 + 0.2 * sin(u_time * 4.0);
    
    // Add a base vignette so edges are darker
    float vignette = 1.0 - smoothstep(0.5, 1.5, length(p));

    // 5. Simulated Noise
    float noise = hash(uv + u_time) * 0.08;

    // Composite Colors
    vec3 baseColor = getLiveColor();
    
    // Start with grid and pulse
    vec3 color = baseColor * (gridAlpha + pulse * 0.4);
    
    // Add interactive glow
    color += baseColor * glow * 0.15;
    
    // Add vignette
    color *= vignette;
    
    // Add scanlines and noise
    color -= scanAlpha;
    color += noise;
    
    // Darken overall to act as a background
    color *= 0.4;
    
    gl_FragColor = vec4(color, 1.0);
  }
`;

function createShader(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) throw new Error("Failed to create shader");
  
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error(gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    throw new Error("Shader compile failed");
  }
  return shader;
}

export function SystemOverrideShader() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const gl = canvas.getContext("webgl");
    if (!gl) {
      console.warn("WebGL not supported");
      return;
    }

    const vertexShader = createShader(gl, gl.VERTEX_SHADER, vertexShaderSource);
    const fragmentShader = createShader(gl, gl.FRAGMENT_SHADER, fragmentShaderSource);

    const program = gl.createProgram();
    if (!program) return;
    
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.error(gl.getProgramInfoLog(program));
      return;
    }

    gl.useProgram(program);

    // Set up full-screen quad
    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([
        -1.0, -1.0,
         1.0, -1.0,
        -1.0,  1.0,
        -1.0,  1.0,
         1.0, -1.0,
         1.0,  1.0,
      ]),
      gl.STATIC_DRAW
    );

    const positionLocation = gl.getAttribLocation(program, "position");
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    const resolutionLocation = gl.getUniformLocation(program, "u_resolution");
    const timeLocation = gl.getUniformLocation(program, "u_time");
    const mouseLocation = gl.getUniformLocation(program, "u_mouse");

    let animationFrameId: number;
    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    
    // Smooth mouse interpolation
    let targetMouseX = mouseX;
    let targetMouseY = mouseY;

    const handleMouseMove = (e: MouseEvent) => {
      targetMouseX = e.clientX;
      targetMouseY = window.innerHeight - e.clientY; // Invert Y for WebGL
    };

    window.addEventListener("mousemove", handleMouseMove);

    const resize = () => {
      // Use devicePixelRatio for crisp rendering on retina displays
      const dpr = window.devicePixelRatio || 1;
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
      gl.viewport(0, 0, canvas.width, canvas.height);
    };

    window.addEventListener("resize", resize);
    resize();

    const startTime = performance.now();

    const render = (time: number) => {
      // Lerp mouse
      mouseX += (targetMouseX - mouseX) * 0.1;
      mouseY += (targetMouseY - mouseY) * 0.1;

      gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
      gl.uniform1f(timeLocation, (time - startTime) * 0.001);
      gl.uniform2f(mouseLocation, mouseX, mouseY);

      gl.drawArrays(gl.TRIANGLES, 0, 6);
      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0 h-full w-full opacity-60 mix-blend-screen"
    />
  );
}
