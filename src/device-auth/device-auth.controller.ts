import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Controller('device-auth')
export class DeviceAuthController {
  @Post('token')
  @HttpCode(200)
  async issueDeviceToken(@Body() body: { device_id: string; zone_id: string; group_id: string; scopes: string[] }) {
    const secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
    const token = jwt.sign(
      { sub: body.device_id, zone_id: body.zone_id, group_id: body.group_id, scopes: body.scopes },
      secret,
      { expiresIn: '30d' },
    );
    return { device_token: token, expires_in: 30 * 24 * 3600 };
  }
}
