<?php

namespace App\Http\Controllers;

use App\Board;
use App\User;
use App\Http\Resources\Board as BoardResource;

use Illuminate\Http\Request;
use Auth;

class BoardController extends Controller
{

    public function __construct(){
        // $this->authorizeResource(Board::class);
    }

    public function index()
    {
        return BoardResource::collection(Auth::user()->boards);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|unique:boards|max:255',
        ]);
        
        $data['user_id'] = Auth::user()->id;
        $board = Board::create($data);

        return response()->json(['created' => true, 'board' => new BoardResource($board)], 201);
    }

    public function show(Board $board)
    {
        return new BoardResource($board);
    }

    public function update(Request $request, Board $board)
    {
        $data = $request->validate([
            'name' => 'nullable|max:255'
        ]);

        $role->update($data);

        return response()->json(['updated' => true, 'board' => new BoardResource($board)], 200);
    }

    public function destroy(Board $board)
    {
        $board->delete();

        return response()->json(['deleted' => true], 204);
    }
}
