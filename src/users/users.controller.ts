import {
  Controller, Get, Post, Put, Delete, Body, Param, Query,
  HttpCode, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard, CurrentUser } from '@campuscast/shared-libs';
import { UsersService, CreateUserDto, UpdateUserDto } from './users.service';
import { RequirePermissions } from '../common/require-permissions.decorator';
import { PermissionsGuard } from '../common/permissions.guard';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @RequirePermissions('users.read')
  async list(
    @Query('page') page = '1',
    @Query('page_size') pageSize = '20',
    @Query('search') search?: string,
    @Query('role') role?: string,
    @Query('status') status?: string,
  ) {
    return this.usersService.list({
      page: Math.max(1, parseInt(page, 10) || 1),
      page_size: Math.min(100, Math.max(1, parseInt(pageSize, 10) || 20)),
      search,
      role,
      status,
    });
  }

  @Get(':id')
  @RequirePermissions('users.read')
  async getById(@Param('id') id: string) {
    return this.usersService.getById(id);
  }

  @Post()
  @RequirePermissions('users.write')
  async create(@Body() body: CreateUserDto, @CurrentUser() actor: { sub: string }) {
    return this.usersService.create(body, actor.sub);
  }

  @Put(':id')
  @RequirePermissions('users.write')
  async update(
    @Param('id') id: string,
    @Body() body: UpdateUserDto,
    @CurrentUser() actor: { sub: string },
  ) {
    return this.usersService.update(id, body, actor.sub);
  }

  @Delete(':id')
  @HttpCode(200)
  @RequirePermissions('users.write')
  async deactivate(@Param('id') id: string, @CurrentUser() actor: { sub: string }) {
    return this.usersService.deactivate(id, actor.sub);
  }

  @Post(':id/restore')
  @RequirePermissions('users.write')
  async restore(@Param('id') id: string, @CurrentUser() actor: { sub: string }) {
    return this.usersService.restore(id, actor.sub);
  }

  @Delete(':id/permanent')
  @HttpCode(200)
  @RequirePermissions('users.write')
  async removePermanently(@Param('id') id: string, @CurrentUser() actor: { sub: string }) {
    return this.usersService.removePermanently(id, actor.sub);
  }
}
