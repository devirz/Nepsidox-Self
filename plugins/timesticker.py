from telethon import events
from client import client
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime
import io

@client.on(events.NewMessage(pattern=r'^[Tt][Ii][Mm][Ee]$'))
async def timesticker(event):
    # Create a new image with white background
    img = Image.new('RGB', (800, 400), color='white')
    draw = ImageDraw.Draw(img)
    
    try:
        # Try to load a font (default system font)
        font = ImageFont.truetype('arial.ttf', 60)
    except:
        # Fallback to default font
        font = ImageFont.load_default()
    
    # Get current time
    current_time = datetime.now().strftime('%H:%M:%S')
    
    # Calculate text size and position for centering
    text_bbox = draw.textbbox((0, 0), current_time, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    
    x = (512 - text_width) // 2
    y = (512 - text_height) // 2
    
    # Draw time on image
    draw.text((x, y), current_time, font=font, fill='black')
    
    # Convert PIL image to bytes
    image_stream = io.BytesIO()
    image_stream.name = 'time.webp'
    img.save(image_stream, 'WebP')
    image_stream.seek(0)
    
    # Send as sticker
    await event.client.send_file(
        event.chat_id,
        image_stream,
        force_document=False,
        allow_cache=False,
        reply_to=event.message,
        attributes=[]
    )