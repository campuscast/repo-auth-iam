import {
  Controller, Get, Post, Put, Body, Param, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard, CurrentUser } from '@campuscast/shared-libs';
import { RolesService } from './roles.service';
import { RequirePermissions } from '../common/require-permissions.decorator';
import { PermissionsGuard } from '../common/permissions.guard';

@Controller('roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Get()
  @RequirePermissions('users.read')
  async list() {
    return this.rolesService.list();
  }

  @Get(':id')
  @RequirePermissions('users.read')
  async getById(@Param('id') id: string) {
    return this.rolesService.getById(id);
  }

  @Post()
  @RequirePermissions('users.write')
  async create(
    @Body() body: { name: string; permissions: string[] },
    @CurrentUser() actor: { sub: string },
  ) {
    return this.rolesService.create(body, actor.sub);
  }

  @Put(':id')
  @RequirePermissions('users.write')
  async update(
    @Param('id') id: string,
    @Body() body: { name?: string; permissions?: string[] },
    @CurrentUser() actor: { sub: string },
  ) {
    return this.rolesService.update(id, body, actor.sub);
  }

  @Post('assign')
  @RequirePermissions('users.write')
  async assign(
    @Body() body: { user_id: string; role_id: string },
    @CurrentUser() actor: { sub: string },
  ) {
    return this.rolesService.assignRoleToUser(body.user_id, body.role_id, actor.sub);
  }

  @Post('remove')
  @RequirePermissions('users.write')
  async remove(
    @Body() body: { user_id: string; role_id: string },
    @CurrentUser() actor: { sub: string },
  ) {
    return this.rolesService.removeRoleFromUser(body.user_id, body.role_id, actor.sub);
  }
}
