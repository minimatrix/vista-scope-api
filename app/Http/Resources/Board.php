<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class Board extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        return [
            'id'                => $this->id,
            'author'            => $this->user,
            'name'           => $this->name,
        ];
    }
}
